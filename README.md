# ebpf-bolt
eBPF tool to collect BOLT profile

# Build instructions
1. Clone libbpf submodule
2. Build libbpf:
```
cd libbpf/src
make
PREFIX=~/local make install
```
3. Build ebpf-bolt tool:
```
cd -
C_INCLUDE_PATH=~/local/include:$C_INCLUDE_PATH make
```
