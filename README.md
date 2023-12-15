# ebpf-bolt: eBPF tool to collect BOLT profile
Collect and aggregate LBR samples using eBPF with minimal profiling overhead.

Output pre-aggregated BOLT profile suitable for optimization (same binary) or conversion to other profile formats (fdata or YAML) that tolerate binary differences.

This tool achieves much lower total overhead compared to perf sampling thanks to the following:
1. LBR samples are processed on-the-fly instead of storing samples into a buffer (typically MBs/GBs) for offline parsing and aggregation by separate tools.
3. LBR parsing and aggregation happen in kernel space eliminating context switches.
4. Aggregated entries are stored in per-CPU hash tables eliminating atomic increments and cache ping-pong effects. Accumulation across CPUs occurs once when the profile is dumped.

## Prerequisites
This tool makes use of LBR for 0-overhead sampling and [eBPF CO-RE](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html#bpf-co-re-compile-once-run-everywhere) for portability.
- CPU: LBR/branch stack sampling support
  - Intel Last Branch Record (LBR): since Pentium 4 Netburst, including all Atom CPUs, Linux 2.6.35.
  - AMD Branch Sampling (BRS): since Zen3 for EPYC, since Zen4 for other, Linux 5.19.
  - ARM Branch Record Buffer Extensions (BRBE): since v9.2-A (Cortex-X4, A720, and A520), Linux v6.1.
- Kernel: Linux 4.16 with `CONFIG_DEBUG_INFO_BTF=y` for BPF CO-RE, 
- Compiler: Clang 10 or GCC 12 with BPF target and CO-RE relocations support.
- xxhash:
  - CentOS: `dnf install xxhash-devel`
  - Ubuntu: `apt install libxxhash-dev`

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
4. Set tracing capabilities to allow non-root operation: 
```
sudo setcap "cap_perfmon=+ep cap_bpf=+ep" ebpf-bolt
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
./ebpf-bolt -p `pgrep app` > preagg.data
llvm-bolt app --pa -p preagg.data ...
```
Note the `--pa` flag instructing BOLT to read pre-aggregated profile.
