# Based off github.com/lizrice/learning-ebpf
TARGET = ebpf-bolt
ARCH = x86

BPF_OBJ = ${TARGET:=.bpf.o}

USER_CC = ${TARGET:=.cc}
USER_SKEL = ${TARGET:=.skel.h}

COMMON_H = ${TARGET:=.h}

app: $(TARGET) $(BPF_OBJ)
.PHONY: app

$(TARGET): $(USER_CC) $(USER_SKEL) $(COMMON_H)
	$(CXX) -Wall -o $(TARGET) $(USER_CC) -L./libbpf/src -l:libbpf.a -lelf -lz -lxxhash \
	    -I${CURDIR}/libbpf/install/include -I${CURDIR}/libbpf/include $(CXXFLAGS)

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
