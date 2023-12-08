# Based off github.com/lizrice/learning-ebpf
TARGET = ebpf-bolt
ARCH = x86

BPF_OBJ = ${TARGET:=.bpf.o}

USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

COMMON_H = ${TARGET:=.h}

app: $(TARGET) $(BPF_OBJ)
.PHONY: app

$(TARGET): $(USER_C) $(USER_SKEL) $(COMMON_H)
	$(CC) -Wall -o $(TARGET) $(USER_C) -L./libbpf/src -l:libbpf.a -lelf -lz \
	    -I${CURDIR}/libbpf/install/include -I${CURDIR}/libbpf/include $(CFLAGS)

%.bpf.o: %.bpf.c vmlinux.h $(COMMON_H)
	clang \
	    -I${CURDIR}/libbpf/install/include \
	    -target bpf \
	    -D __BPF_TRACING__ \
      -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
	- rm $(USER_SKEL)
	- rm vmlinux.h
