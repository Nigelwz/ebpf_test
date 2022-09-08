DEP := dep
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath $(DEP)/libbpf.a)
BPFTOOL_SRC := $(abspath ./bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath $(DEP)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := ./vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(DEP) -I./libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
APPS = kprobe
.PHONY: all
all: $(APPS)
.PHONY: clean
clean:
	rm -rf $(DEP) $(APPS) *.o
$(DEP) $(DEP)/libbpf $(BPFTOOL_OUTPUT):
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
kprobe.bpf.o: kprobe.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(DEP)
	#$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c kprobe.bpf.c -o kprobe.bpf.o
	$(LLVM_STRIP) -g $@ # strip useless DWARF info
# Generate BPF skeletons
kprobe.skel.h: kprobe.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@
# Build user-space code
$(patsubst %,./%.o,$(APPS)): %.o: %.skel.h

%.o: %.c $(wildcard %.h) | $(DEP)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@
# Build application binary
$(APPS): kprobe.o $(LIBBPF_OBJ) | $(DEP)
	$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@
