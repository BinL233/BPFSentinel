# Makefile for Visor - eBPF Compute Throttling System
# Combines Token Bucket architecture with Client-Side Throttling

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CC ?= gcc

# Directories
OUTPUT := .output
LIBBPF_SRC := /usr/include
LIBBPF_OBJ := $(abspath ../../libbpf/src)

# Architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Flags
INCLUDES := -I$(LIBBPF_SRC) -I$(OUTPUT) -I. -I/usr/include/bpf
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
USER_CFLAGS := -g -O2 -Wall
LDFLAGS := -lbpf -lelf -lz

# Targets
BPF_PROGS := throttled_prog.bpf.o
USER_PROGS := visor_controller

.PHONY: all clean vmlinux

all: $(OUTPUT) vmlinux $(BPF_PROGS) $(USER_PROGS)

$(OUTPUT):
	@mkdir -p $(OUTPUT)

# Generate vmlinux.h from BTF
vmlinux: $(OUTPUT)/vmlinux.h

$(OUTPUT)/vmlinux.h:
	@if command -v bpftool >/dev/null 2>&1; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(OUTPUT)/vmlinux.h; \
		echo "Generated vmlinux.h"; \
	else \
		echo "Warning: bpftool not found, vmlinux.h not generated"; \
	fi

# Compile BPF programs
%.bpf.o: %.bpf.c throttle.h $(OUTPUT)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
	@echo "Compiled $@ successfully"

# Compile user-space controller
visor_controller: visor_controller.c throttle.h
	$(CC) $(USER_CFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS)
	@echo "Compiled $@ successfully"

# Clean build artifacts
clean:
	rm -rf $(OUTPUT)
	rm -f $(BPF_PROGS) $(USER_PROGS)
	rm -f *.o
	@echo "Cleaned build artifacts"

# Install (optional)
install: all
	@echo "Installing visor components..."
	@sudo install -m 755 visor_controller /usr/local/bin/
	@sudo mkdir -p /usr/local/lib/bpf
	@sudo install -m 644 throttled_prog.bpf.o /usr/local/lib/bpf/
	@echo "Installation complete"

# Help
help:
	@echo "Visor - eBPF Compute Throttling System"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build all components (default)"
	@echo "  vmlinux          - Generate vmlinux.h from BTF"
	@echo "  clean            - Remove build artifacts"
	@echo "  install          - Install binaries to system"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  1. make vmlinux  - Generate kernel headers"
	@echo "  2. make          - Build BPF program and controller"
	@echo "  3. sudo ./visor_controller [prog_id]"
