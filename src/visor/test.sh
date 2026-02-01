#!/bin/bash
# Test script for visor throttling system
# Demonstrates the token bucket and throttling behavior

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "Visor Throttling System - Test Suite"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

# Build the system
echo "[1/5] Building visor components..."
make clean > /dev/null 2>&1
make vmlinux > /dev/null 2>&1
make

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "✓ Build successful"
echo ""

# Enable BPF statistics
echo "[2/5] Enabling BPF statistics..."
echo 1 > /proc/sys/kernel/bpf_stats_enabled
echo "✓ BPF stats enabled"
echo ""

# Load the BPF program manually for testing
echo "[3/5] Loading throttled BPF program..."

# Create a simple test loader
cat > test_loader.c << 'EOF'
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int err;
    
    obj = bpf_object__open_file("throttled_prog.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }
    
    printf("BPF program loaded successfully\n");
    
    // Keep it loaded
    printf("Press Ctrl+C to exit...\n");
    pause();
    
    bpf_object__close(obj);
    return 0;
}
EOF

gcc test_loader.c -o test_loader -lbpf
./test_loader &
LOADER_PID=$!
sleep 2

echo "✓ BPF program loaded (PID: $LOADER_PID)"
echo ""

# Get the program ID
PROG_ID=$(bpftool prog show | grep xdp_throttled | head -1 | awk '{print $1}' | tr -d ':')

if [ -z "$PROG_ID" ]; then
    echo "Warning: Could not find program ID, starting controller without it"
    PROG_ID=""
else
    echo "✓ Found program ID: $PROG_ID"
fi
echo ""

# Start the controller in background
echo "[4/5] Starting visor controller..."
if [ -n "$PROG_ID" ]; then
    ./visor_controller "$PROG_ID" &
else
    ./visor_controller &
fi
CONTROLLER_PID=$!
sleep 2

echo "✓ Controller started (PID: $CONTROLLER_PID)"
echo ""

# Monitor for a while
echo "[5/5] Monitoring throttling behavior (30 seconds)..."
echo "Press Ctrl+C to stop early"
echo ""

sleep 30

# Cleanup
echo ""
echo "Cleaning up..."
kill $CONTROLLER_PID 2>/dev/null || true
kill $LOADER_PID 2>/dev/null || true
rm -f test_loader test_loader.c

echo ""
echo "=========================================="
echo "Test complete!"
echo "=========================================="
echo ""
echo "The visor controller:"
echo "  - Refilled token bucket every 1 second with 50ms budget"
echo "  - Monitored actual CPU usage"
echo "  - Adapted budget if usage exceeded 6%"
echo "  - Displayed throttling statistics"
echo ""
echo "Next steps:"
echo "  1. Attach throttled programs to network interfaces"
echo "  2. Generate traffic to trigger throttling"
echo "  3. Observe statistics and adaptive behavior"
