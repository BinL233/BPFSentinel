#!/usr/bin/env bash

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "[ERROR] Must run as root" >&2
  exit 1
fi

# Interface can be passed as arg or via IFACE env; defaults to lima0
IFACE_DEFAULT="lima0"
IFACE="${1:-${IFACE:-$IFACE_DEFAULT}}"

PIN_DIR="/sys/fs/bpf/links"
CGROUP_PATH=${SOCKOPS_CGROUP_PATH:-/sys/fs/cgroup}
CONFIG_PATH="../configs/config.json"

log() {
  echo "[cleanup] $*"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# Check if wrappers are enabled in config
get_use_wrappers() {
  if have_cmd jq; then
    jq -r '.use_wrappers // false' "$CONFIG_PATH" 2>/dev/null || echo "false"
  else
    python3 - "$CONFIG_PATH" <<'PY'
import json,sys
try:
  with open(sys.argv[1],'r') as f:
    d=json.load(f)
  print('true' if d.get('use_wrappers',False) else 'false')
except:
  print('false')
PY
  fi
}

# Read targets from config.json -> lines: name|type|fentry|fexit
get_targets() {
  if have_cmd jq; then
    jq -r '.targets[] | "\(.name)|\(.type)|\(.fentry_name)|\(.fexit_name)"' "$CONFIG_PATH"
  else
    python3 - "$CONFIG_PATH" <<'PY'
import json,sys
p=sys.argv[1]
with open(p,'r') as f:
  d=json.load(f)
for t in d.get('targets',[]):
  n=t.get('name','') or ''
  ty=t.get('type','') or ''
  fe=t.get('fentry_name','') or ''
  fx=t.get('fexit_name','') or ''
  print(f"{n}|{ty}|{fe}|{fx}")
PY
  fi
}

# Load config into arrays
declare -a T_NAMES
declare -a T_TYPES
declare -a T_FENTRY
declare -a T_FEXIT
idx=0
while IFS='|' read -r n ty fe fx; do
  if [ -z "$n" ] || [ -z "$ty" ]; then
    continue
  fi
  T_NAMES[$idx]="$n"
  T_TYPES[$idx]="${ty,,}"
  T_FENTRY[$idx]="$fe"
  T_FEXIT[$idx]="$fx"
  idx=$((idx+1))
done < <(get_targets)

if [ ${#T_NAMES[@]} -eq 0 ]; then
  log "No targets found in $CONFIG_PATH; nothing to do."
  exit 0
fi

# Helper: check if a name matches any tracer fentry/fexit names from config
is_tracer_name() {
  local q="$1"
  local i=0
  while [ $i -lt ${#T_NAMES[@]} ]; do
    if [ "$q" = "${T_FENTRY[$i]}" ] || [ "$q" = "${T_FEXIT[$i]}" ]; then
      return 0
    fi
    i=$((i+1))
  done
  return 1
}

log "Stopping running loader/tracer processes for this project..."
for pname in tracer_loader target_loader wrapper_loader; do
  pids=$(pgrep -f "$pname" || true)
  if [ -n "$pids" ]; then
    log "Killing $pname PIDs: $pids"
    kill $pids 2>/dev/null || true
    sleep 0.5
    pids2=$(pgrep -f "$pname" || true)
    if [ -n "$pids2" ]; then
      kill -9 $pids2 2>/dev/null || true
    fi
  fi
done

# XDP: detach if program matches target OR wrapper name
detach_xdp_if_match() {
  local want="$1"
  local cur=""
  if have_cmd jq; then
    cur=$(ip -j link show dev "$IFACE" 2>/dev/null | jq -r '.[0].xdp.prog.name // empty' || true)
  else
    cur=$(ip -details link show dev "$IFACE" 2>/dev/null | awk '/prog xdp/{for(i=1;i<=NF;i++){if($i=="name"){print $(i+1);break}}}' || true)
  fi
  # Check if current matches target name OR is xdp_wrapper
  if [ -n "$cur" ] && { [ "$cur" = "$want" ] || [ "$cur" = "xdp_wrapper" ]; }; then
    log "Detaching XDP '$cur' from $IFACE (match '$want' or wrapper)"
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    ip link set dev "$IFACE" xdpoffload off 2>/dev/null || true
    ip link set dev "$IFACE" xdpdrv off 2>/dev/null || true
  else
    log "Skip XDP detach on $IFACE (current='$cur', want='$want')"
  fi
}

# TC: remove filters matching target OR wrapper name (or ALL if wrappers enabled)
detach_tc_if_match() {
  local want_name="$1"
  local use_wrappers="$2"
  
  # If wrappers enabled, remove ALL TC filters on ingress
  if [ "$use_wrappers" = "true" ]; then
    log "Removing ALL TC ingress filters (wrappers enabled)"
    tc filter del dev "$IFACE" ingress 2>/dev/null || true
    return 0
  fi
  
  # Prefer JSON path: find bpf filters, read their program id, map to name via bpftool, delete on match
  if have_cmd jq && have_cmd bpftool; then
    local entries
    entries=$(tc -j filter show dev "$IFACE" ingress 2>/dev/null | jq -c '.[] | select(.kind=="bpf") | {pref:.pref,handle:(.options.handle // .handle // empty),id:(.options.prog.id // .options.id // empty)}' || true)
    if [ -n "${entries:-}" ]; then
      while read -r ent; do
        if [ -z "$ent" ]; then
          continue
        fi
        local pref handle pid pname
        pref=$(echo "$ent" | jq -r '.pref')
        handle=$(echo "$ent" | jq -r '.handle // empty')
        pid=$(echo "$ent" | jq -r '.id // empty')
        if [ -z "$pid" ]; then
          continue
        fi
        pname=$(bpftool prog show id "$pid" -j 2>/dev/null | jq -r '.name // empty' || true)
        # Match target name OR tc_wrapper
        if [ -n "$pname" ] && { [ "$pname" = "$want_name" ] || [ "$pname" = "tc_wrapper" ]; }; then
          if [ -n "$handle" ] && [ "$handle" != "null" ] && [ "$handle" != "empty" ]; then
            log "Deleting TC bpf filter pref=$pref handle=$handle (prog=$pname id=$pid)"
            tc filter del dev "$IFACE" ingress pref "$pref" handle "$handle" bpf 2>/dev/null || true
          else
            log "Deleting TC bpf filter pref=$pref (prog=$pname id=$pid)"
            tc filter del dev "$IFACE" ingress pref "$pref" bpf 2>/dev/null || true
          fi
        fi
      done <<< "$entries"
    fi
  else
    # Text fallback: parse pref/handle/id and verify prog name
    local cur_pref="" cur_handle="" cur_id=""
    while IFS= read -r line; do
      if echo "$line" | grep -q "^filter"; then
        cur_pref=$(echo "$line" | awk '{for(i=1;i<=NF;i++){if($i=="pref"){print $(i+1);break}}}')
        cur_handle=$(echo "$line" | awk '{for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1);break}}}')
      fi
      if echo "$line" | grep -q " bpf "; then
        cur_id=$(echo "$line" | awk '{for(i=1;i<=NF;i++){if($i=="id"){print $(i+1);break}}}')
        if have_cmd bpftool && [ -n "$cur_id" ]; then
          pname=$(bpftool prog show id "$cur_id" 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="name"){print $(i+1);break}}}')
          # Match target name OR tc_wrapper
          if [ -n "$pname" ] && { [ "$pname" = "$want_name" ] || [ "$pname" = "tc_wrapper" ]; }; then
            if [ -n "$cur_handle" ]; then
              log "Deleting TC bpf filter pref=$cur_pref handle=$cur_handle (prog=$pname id=$cur_id)"
              tc filter del dev "$IFACE" ingress pref "$cur_pref" handle "$cur_handle" bpf 2>/dev/null || true
            else
              log "Deleting TC bpf filter pref=$cur_pref (prog=$pname id=$cur_id)"
              tc filter del dev "$IFACE" ingress pref "$cur_pref" bpf 2>/dev/null || true
            fi
          fi
        fi
      fi
    done < <(tc filter show dev "$IFACE" ingress 2>/dev/null || true)
  fi
}

# KPROBE/FENTRY targets: unpin their specific links only
unpin_link_if_exists() {
  local name="$1"
  local p="$PIN_DIR/$name"
  if [ -e "$p" ]; then
    rm -f "$p" && log "Unpinned link $p"
  fi
}

# SOCKOPS: detach target OR wrapper programs (or ALL if wrappers enabled)
detach_sockops_by_name() {
  local want="$1"
  local use_wrappers="$2"
  
  if have_cmd bpftool; then
    local ids
    if [ "$use_wrappers" = "true" ]; then
      # Remove ALL sock_ops programs when wrappers enabled
      log "Removing ALL sock_ops programs (wrappers enabled)"
      if have_cmd jq; then
        ids=$(bpftool prog show -j 2>/dev/null | jq -r '.[] | select(.type=="sock_ops") | .id' || true)
      else
        ids=$(bpftool prog show 2>/dev/null | awk '/sock_ops/{getline; if($1 ~ /^[0-9]+:$/){id=$1; gsub(":","",id); print id}}' || true)
      fi
    else
      # Only remove matching programs
      if have_cmd jq; then
        ids=$(bpftool prog show -j 2>/dev/null | jq -r '.[] | select(.type=="sock_ops" and (.name=="'"$want"'" or .name=="sockops_wrapper")) | .id' || true)
      else
        ids=$(bpftool prog show 2>/dev/null | awk 'BEGIN{keep=0} /^[0-9]+:/{id=$1; gsub(":","",id)} /sock_ops/{keep=1} /name/{if(keep){nm=$2; if(nm=="'"$want"'" || nm=="sockops_wrapper"){print id}}; keep=0}' || true)
      fi
    fi
    
    if [ -n "${ids:-}" ]; then
      while read -r id; do
        if [ -n "$id" ]; then
          log "Detaching sock_ops id=$id from $CGROUP_PATH"
          bpftool cgroup detach "$CGROUP_PATH" sock_ops id "$id" 2>/dev/null || true
        fi
      done <<< "$ids"
    else
      log "No sock_ops programs found"
    fi
  else
    log "bpftool not found; skipping sockops detach"
  fi
}

# Detach tracer fentry/fexit links by program name from config
detach_tracer_links() {
  if ! have_cmd bpftool; then
    log "bpftool not found; skipping tracer link detach"
    return 0
  fi
  if have_cmd jq; then
    link_ids=$(bpftool link show -j 2>/dev/null | jq -r '.[] | select(.type=="tracing") | .id' || true)
    if [ -z "${link_ids:-}" ]; then
      return 0
    fi
    while read -r lid; do
      if [ -z "$lid" ]; then
        continue
      fi
      pid=$(bpftool link show id "$lid" -j 2>/dev/null | jq -r '.[0].prog_id // .prog_id // empty' || true)
      if [ -z "$pid" ]; then
        continue
      fi
      pname=$(bpftool prog show id "$pid" -j 2>/dev/null | jq -r '.name // empty' || true)
      if [ -n "$pname" ] && is_tracer_name "$pname"; then
        log "Detaching tracer link id=$lid (prog=$pname)"
        bpftool link detach id "$lid" 2>/dev/null || true
      fi
    done <<< "$link_ids"
  else
    # Text fallback: best-effort
    while read -r line; do
      case "$line" in
        *tracing*)
          lid=$(echo "$line" | awk '{print $2}' | tr -d ':')
          pid=$(echo "$line" | awk '{for(i=1;i<=NF;i++){if($i=="prog"){print $(i+1);break}}}' | tr -d ':')
          if [ -n "$pid" ]; then
            pname=$(bpftool prog show id "$pid" 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="name"){print $(i+1);break}}}')
            if [ -n "$pname" ] && is_tracer_name "$pname"; then
              log "Detaching tracer link id=$lid (prog=$pname)"
              bpftool link detach id "$lid" 2>/dev/null || true
            fi
          fi
        ;;
      esac
    done < <(bpftool link show 2>/dev/null)
  fi
}

log "Applying scoped cleanup for targets in $CONFIG_PATH on IFACE=$IFACE"

# Check if wrappers are enabled
USE_WRAPPERS=$(get_use_wrappers)
if [ "$USE_WRAPPERS" = "true" ]; then
  log "Wrappers enabled - using aggressive cleanup"
fi

# Iterate targets and perform type-specific scoped cleanup
i=0
while [ $i -lt ${#T_NAMES[@]} ]; do
  name="${T_NAMES[$i]}"
  t="${T_TYPES[$i]}"
  case "$t" in
    xdp)
      detach_xdp_if_match "$name"
      ;;
    tc)
      detach_tc_if_match "$name" "$USE_WRAPPERS"
      ;;
    kprobe)
      unpin_link_if_exists "$name"
      ;;
    fentry)
      unpin_link_if_exists "$name"
      ;;
    sockops)
      detach_sockops_by_name "$name" "$USE_WRAPPERS"
      ;;
    *)
      ;;
  esac
  i=$((i+1))
done

# Also ensure tracer programs are detached
log "Detaching tracing programs from config (fentry/fexit)"
detach_tracer_links

# Remove any pinned tracer links matching config tracer names
i=0
while [ $i -lt ${#T_NAMES[@]} ]; do
  if [ -n "${T_FENTRY[$i]}" ]; then
    unpin_link_if_exists "${T_FENTRY[$i]}"
  fi
  if [ -n "${T_FEXIT[$i]}" ]; then
    unpin_link_if_exists "${T_FEXIT[$i]}"
  fi
  i=$((i+1))
done

# Clean up wrapper-specific pinned resources
log "Cleaning up wrapper pinned maps..."
for map_name in token_bucket stats_map prog_array; do
  map_path="/sys/fs/bpf/$map_name"
  if [ -e "$map_path" ]; then
    rm -f "$map_path" && log "Removed pinned map $map_path"
  fi
done

# Remove wrapper pinned links if any
for wrapper_name in xdp_wrapper tc_wrapper kprobe_wrapper sockops_wrapper fentry_wrapper; do
  unpin_link_if_exists "$wrapper_name"
done

log "Scoped cleanup complete."
