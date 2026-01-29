#!/bin/bash

set -euo pipefail

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: Please run as root (sudo)"
    exit 1
fi

echo -e "\n=== Running BPF Tracer ==="

# Check if interface specified (default to lima0)
INTERFACE="${1:-lima0}"

# Cleanup function to ensure attached BPF programs/links/maps are removed on exit
cleanup() {
    echo -e "\n[cleanup] running cleanup..."
    # Attempt to stop tracer/target loaders if still running
    pkill -f tracer_loader || true
    pkill -f target_loader || true

    # Uninstall TC classifier
    if command -v ./tracers/uninstall_tc.sh >/dev/null 2>&1; then
        ./tracers/uninstall_tc.sh "$INTERFACE" || true
    fi

    # Remove pinned XDP link and shared map
    if [ -e /sys/fs/bpf/links/xdp_handler ]; then
        echo "[cleanup] removing pinned xdp link"
        rm -f /sys/fs/bpf/links/xdp_handler || true
    fi
    # (trace_info map removed in new workflow; ring buffer not pinned)

    # Ensure device has XDP off
    ip link set dev "$INTERFACE" xdp off 2>/dev/null || true

    echo "[cleanup] done."
}

# Ensure cleanup runs on exit or when script receives SIGINT/SIGTERM
trap cleanup EXIT INT TERM

echo -e "Attaching programs on interface: $INTERFACE"
echo ""

echo "[run] Detaching any existing XDP program (pre-clean)"
ip link set dev "$INTERFACE" xdp off 2>/dev/null || true

echo "[run] Attaching targets via dispatcher (.output/target_loader)"
if [ -x .output/target_loader ]; then
    if ! .output/target_loader "$INTERFACE" configs/config.json; then
        echo "[run] ERROR: target_loader failed" >&2
        exit 1
    fi
else
    echo "[run] ERROR: target_loader binary missing" >&2
    exit 1
fi

echo "[run] Attempting to start tracer loader"
if [ -x .output/tracer_loader ]; then
    .output/tracer_loader configs/config.json || echo "[run] tracer_loader failed"
else
    echo "[run] tracer_loader binary missing; build skipped or failed"
fi

echo "Done!"