# ebpf-bolt
eBPF tool to collect BOLT profile

# Build instructions
1. Clone libbpf submodule
2. Build libbpf:
```
cd libbpf/src
PREFIX=../install make install
```
3. Build ebpf-bolt tool:
```
cd -
make
```
