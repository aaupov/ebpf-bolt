# ebpf-bolt: eBPF tool to collect BOLT profile
Collect and aggregate LBR samples using eBPF with minimal profiling overhead.

Output pre-aggregated BOLT profile suitable for optimization (same binary) or conversion to other profile formats (fdata or YAML) that tolerate binary differences.

This tool achieves much lower total overhead compared to perf sampling thanks to the following:
1. LBR samples are processed on-the-fly instead of storing samples into a buffer (typically MBs/GBs) for offline parsing and aggregation by separate tools.
3. LBR parsing and aggregation happen in kernel space eliminating context switches.
4. Aggregated entries are stored in per-CPU hash tables eliminating atomic increments and cache effects. Accumulation across CPUs occurs once when the profile is dumped.

## Prerequisites
This tool makes use of [eBPF CO-RE](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html#bpf-co-re-compile-once-run-everywhere) for portability.
- Kernel: Linux 4.16+ with `CONFIG_DEBUG_INFO_BTF=y`.
- Compiler: Clang 10+ or GCC 12+ with BPF target and CO-RE relocations support.

## Build instructions
1. Clone this repository with libbpf submodule: 
```
git clone --recurse-submodules https://github.com/aaupov/ebpf-bolt
```
2. Build libbpf:
```
cd ebpf-bolt
cd libbpf/src
PREFIX=../install make install
```
3. Build ebpf-bolt tool:
```
cd ..
make
```

## Usage

```
$ ./ebpf-bolt -h
Usage: ebpf-bolt [OPTION...]
Collect pre-aggregated BOLT profile.

USAGE: ebpf-bolt [-f FREQUENCY (99Hz)] -p PID [duration (10s)]

  -f, --frequency=FREQUENCY  Sample with a certain frequency
  -p, --pid=PID              Sample on this PID only
  -v, --verbose              Verbose debug output
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

Report bugs to https://github.com/aaupov/ebpf-bolt/issues.
```

Example usage:
```
sudo ./ebpf-bolt -p `pgrep app` > preagg.data
llvm-bolt app --pa -p preagg.data ...
```
Note the `--pa` flag instructing BOLT to read pre-aggregated profile.
