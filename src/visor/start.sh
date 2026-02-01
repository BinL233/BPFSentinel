#!/bin/bash
# Visor startup script
# Starts the eBPF compute throttling controller

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

# Build if necessary
if [ ! -f "visor_controller" ] || [ ! -f "throttled_prog.bpf.o" ]; then
    echo "Building visor components..."
    make clean
    make vmlinux
    make
fi

# Enable BPF statistics
echo "Enabling BPF statistics..."
echo 1 > /proc/sys/kernel/bpf_stats_enabled || true

# Parse arguments
PROG_ID=""
if [ $# -gt 0 ]; then
    PROG_ID="$1"
    echo "Starting visor controller with program ID: $PROG_ID"
else
    echo "Starting visor controller (no specific program ID)"
fi

# Start the controller
echo "Starting eBPF compute throttling controller..."
if [ -n "$PROG_ID" ]; then
    ./visor_controller "$PROG_ID"
else
    ./visor_controller
fi

# Cleanup on exit
echo "Controller stopped, cleaning up..."
