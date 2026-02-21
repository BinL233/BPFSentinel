CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
CC ?= gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
LIBBPF_LIB ?= /lib/x86_64-linux-gnu/libbpf.so.0

# Include directories for BPF headers
INCLUDES := -I. -I.. -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

# Compiler flags for BPF
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

# Output directory
OUTPUT := .output
XDP_OBJ := $(OUTPUT)/xdp_handler.o
XDP2_OBJ := $(OUTPUT)/xdp_handler_2.o
TRACE_OBJ := $(OUTPUT)/trace_xdp.o
TC_OBJ := $(OUTPUT)/tc_handler.o
TRACE_TC_OBJ := $(OUTPUT)/trace_tc.o
TRACE_KPROBE_OBJ := $(OUTPUT)/trace_kprobe.o
TRACE_FENTRY_OBJ := $(OUTPUT)/trace_fentry.o
TRACE_SOCKOPS_OBJ := $(OUTPUT)/trace_sockops.o
KPROBE_OBJ := $(OUTPUT)/kprobe_handler.o
FENTRY_OBJ := $(OUTPUT)/fentry_handler.o
SOCKOPS_OBJ := $(OUTPUT)/sockops_handler.o
TARGET_LOADER := $(OUTPUT)/target_loader
TRACER_LOADER := $(OUTPUT)/tracer_loader
WRAPPER_LOADER := $(OUTPUT)/wrapper_loader

# Wrapper objects
XDP_WRAPPER_OBJ := $(OUTPUT)/xdp_wrapper.o
TC_WRAPPER_OBJ := $(OUTPUT)/tc_wrapper.o
KPROBE_WRAPPER_OBJ := $(OUTPUT)/kprobe_wrapper.o
SOCKOPS_WRAPPER_OBJ := $(OUTPUT)/sockops_wrapper.o
FENTRY_WRAPPER_OBJ := $(OUTPUT)/fentry_wrapper.o

.PHONY: all clean wrappers

all: $(OUTPUT) $(XDP_OBJ) $(XDP2_OBJ) $(TRACE_OBJ) $(TRACER_LOADER) $(TARGET_LOADER) $(WRAPPER_LOADER)

# also build TC and other target programs
all: $(TC_OBJ) $(TRACE_TC_OBJ) $(KPROBE_OBJ) $(FENTRY_OBJ) $(SOCKOPS_OBJ)

# Build wrappers
all: wrappers

wrappers: $(OUTPUT) $(XDP_WRAPPER_OBJ) $(TC_WRAPPER_OBJ) $(KPROBE_WRAPPER_OBJ) $(SOCKOPS_WRAPPER_OBJ) $(FENTRY_WRAPPER_OBJ)

$(OUTPUT):
	mkdir -p $(OUTPUT)

# Build XDP program (from targets/)
$(XDP_OBJ): ../targets/xdp_handler.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build second XDP program (from targets/)
$(XDP2_OBJ): ../targets/xdp_handler_2.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build tracing program (from tracers/)
$(TRACE_OBJ): tracers/trace_xdp.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build TC program (from targets/)
$(TC_OBJ): ../targets/tc_handler.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build TC tracing program (from tracers/)
$(TRACE_TC_OBJ): tracers/trace_tc.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build kprobe tracing program
$(TRACE_KPROBE_OBJ): tracers/trace_kprobe.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build fentry tracing program
$(TRACE_FENTRY_OBJ): tracers/trace_fentry.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build sockops tracing program
$(TRACE_SOCKOPS_OBJ): tracers/trace_sockops.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build kprobe example program
$(KPROBE_OBJ): ../targets/kprobe_handler.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build fentry example program
$(FENTRY_OBJ): ../targets/fentry_handler.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Build sock_ops example program
$(SOCKOPS_OBJ): ../targets/sockops_handler.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

## Tracer loader
$(TRACER_LOADER): tracers/loaders/tracer_loader.c tracers/loaders/xdp_tracer_loader.c tracers/loaders/tc_tracer_loader.c tracers/loaders/kprobe_tracer_loader.c tracers/loaders/sockops_tracer_loader.c tracers/loaders/fentry_tracer_loader.c tracers/loaders/tracer_loader.h ../utils/cJSON.c $(TRACE_OBJ) $(TRACE_TC_OBJ) $(TRACE_KPROBE_OBJ) $(TRACE_SOCKOPS_OBJ) $(TRACE_FENTRY_OBJ)
	$(CC) -g -Wall -I.. tracers/loaders/tracer_loader.c tracers/loaders/xdp_tracer_loader.c tracers/loaders/tc_tracer_loader.c tracers/loaders/kprobe_tracer_loader.c tracers/loaders/sockops_tracer_loader.c tracers/loaders/fentry_tracer_loader.c ../utils/cJSON.c -o $@ $(LIBBPF_LIB) -lelf -lz -Wl,-rpath,/lib/x86_64-linux-gnu -Wl,-rpath-link,/lib/x86_64-linux-gnu


## Target dispatcher loader
$(TARGET_LOADER): ../targets/loaders/target_loader.c ../targets/loaders/xdp_loader.c ../targets/loaders/tc_loader.c ../targets/loaders/kprobe_loader.c ../targets/loaders/sockops_loader.c ../targets/loaders/fentry_loader.c ../utils/cJSON.c $(XDP_OBJ) $(XDP2_OBJ) $(TC_OBJ) $(KPROBE_OBJ) $(SOCKOPS_OBJ) $(FENTRY_OBJ)
	$(CC) -g -Wall -I.. ../targets/loaders/target_loader.c ../targets/loaders/xdp_loader.c ../targets/loaders/tc_loader.c ../targets/loaders/kprobe_loader.c ../targets/loaders/sockops_loader.c ../targets/loaders/fentry_loader.c ../utils/cJSON.c -o $@ $(LIBBPF_LIB) -lelf -lz -Wl,-rpath,/lib/x86_64-linux-gnu -Wl,-rpath-link,/lib/x86_64-linux-gnu

## Wrapper loader
$(WRAPPER_LOADER): ../wrapper/loaders/wrapper_loader.c ../utils/cJSON.c $(XDP_WRAPPER_OBJ) $(TC_WRAPPER_OBJ) $(KPROBE_WRAPPER_OBJ) $(SOCKOPS_WRAPPER_OBJ) $(FENTRY_WRAPPER_OBJ)
	$(CC) -g -Wall -I.. ../wrapper/loaders/wrapper_loader.c ../utils/cJSON.c -o $@ $(LIBBPF_LIB) -lelf -lz -Wl,-rpath,/lib/x86_64-linux-gnu -Wl,-rpath-link,/lib/x86_64-linux-gnu

# Build wrapper programs (from ../wrapper/)
$(XDP_WRAPPER_OBJ): ../wrapper/xdp_wrapper.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(TC_WRAPPER_OBJ): ../wrapper/tc_wrapper.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(KPROBE_WRAPPER_OBJ): ../wrapper/kprobe_wrapper.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(SOCKOPS_WRAPPER_OBJ): ../wrapper/sockops_wrapper.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(FENTRY_WRAPPER_OBJ): ../wrapper/fentry_wrapper.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -rf $(OUTPUT)

# Generate vmlinux.h if needed
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
