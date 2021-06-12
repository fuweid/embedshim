# SPDX-License-Identifier: Apache-2.0

CLANG ?= clang
LLVM_STRIP ?= llvm-strip

OUTPUT := .output
LIBBPF_SRC := $(abspath libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)

VMLINUX := vmlinux/vmlinux.h
INCLUDES := -I$(OUTPUT) -I./libbpf/include/uapi -I$(dir $(VMLINUX))

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')


# quiet or not
ifeq ($(V),1)
	Q =
else
	Q = @
endif

APPS := example

BINARIES=$(patsubst %,$(OUTPUT)/%.bpf.o,$(APPS))

.PHONY: binaries
binaries: $(BINARIES)

.PHONY: clean
clean:
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(Q)echo $@
	$(Q)$(CLANG) -g -O2 -target bpf		\
		-D__TARGET_ARCH_$(ARCH)			\
		$(INCLUDES)						\
		-c $(filter %.c,$^)				\
		-o $@
	$(Q)$(LLVM_STRIP) -g $@

$(OUTPUT) $(OUTPUT)/libbpf:
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		\
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		\
		INCLUDEDIR= LIBDIR= UAPIDIR=					\
		install

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate targets
.SECONDARY:
