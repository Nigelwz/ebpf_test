DEP := dep
OBJ_DIR := obj
CLANG ?= clang-12
LLVM_STRIP ?= llvm-strip
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath $(DEP)/libbpf.a)
BPFTOOL_SRC := $(abspath ./bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath $(DEP)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := ./vmlinux/$(ARCH)/vmlinux.h
BPF_H_DIR := bpf_h_file
CC := g++
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(DEP) -I ./ -I./libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
APPS = sys_sensor
.PHONY: all
all: $(APPS)
.PHONY: clean
clean:
	rm -rf $(DEP) $(APPS) $(BPF_H_DIR) $(OBJ_DIR)
$(DEP) $(DEP)/libbpf $(BPFTOOL_OUTPUT) $(BPF_H_DIR) $(OBJ_DIR):
	@mkdir -p $@
# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(DEP)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		\
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)	\
		    INCLUDEDIR= LIBDIR= UAPIDIR=		\
		    install
# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap
# Build BPF code
$(OBJ_DIR)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(DEP)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -DCORE -c $(filter %.c,$^) -o $@
	#$(LLVM_STRIP) -g $@ # strip useless DWARF info
# Generate BPF skeletons
$(BPF_H_DIR)/%.skel.h: $(OBJ_DIR)/%.bpf.o | $(OBJ_DIR) $(BPFTOOL) $(BPF_H_DIR)
	$(BPFTOOL) gen skeleton $< > $@
# Build user-space code
$(patsubst %,$(OBJ_DIR)/%.o,$(APPS)): %.o:

$(OBJ_DIR)/%.o: %.cpp $(BPF_H_DIR)/%.skel.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.cpp,$^) -o $@

# Build application binary
$(APPS): %: $(OBJ_DIR)/%.o $(LIBBPF_OBJ) | $(OBJ_DIR)
	$(CC) -g $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@
