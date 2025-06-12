# ebpf-bolt: eBPF tool to collect BOLT profile
Collect and aggregate LBR samples using eBPF with minimal profiling overhead.

Output pre-aggregated BOLT profile suitable for optimizing the profiled binary or converting to other profile formats (fdata or YAML) that can be used with a different binary.

This tool enables quicker profiling + optimization turnaround time thanks to processing LBR samples on the fly and producing pre-aggregated profile at the end of profiling step, ready to be directly consumed by BOLT. 

## Limitations
1. Collecting the profile for shared libraries is not yet supported (perf2bolt limitation).
2. PIE support is experimental.
3. Only ELF64 (64-bit) binaries are supported. ELF32 (32-bit) binaries are not supported (BOLT limitation).

## Prerequisites
This tool makes use of LBR for 0-overhead sampling and [eBPF CO-RE](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html#bpf-co-re-compile-once-run-everywhere) for portability.
- CPU: LBR/branch stack sampling support
  - Intel Last Branch Record (LBR): since Pentium 4 Netburst, including all Atom CPUs, Linux 2.6.35.
  - AMD LBRv2: since Zen4, Linux v6.1.
  - AMD Branch Sampling (BRS): since Zen3 for EPYC, Linux 5.19. Untested.
  - ARM Branch Record Buffer Extensions (BRBE): since v9.2-A (Cortex-X4, A720, and A520), Linux v6.1.
- Kernel: Linux 4.16 with `CONFIG_DEBUG_INFO_BTF=y` for BPF CO-RE, 
- Compiler: Clang 10 or GCC 12 with BPF target and CO-RE relocations support.
- xxhash and libelf:
  - CentOS: `dnf install xxhash-devel elfutils-libelf-devel`
  - Ubuntu: `apt install libxxhash-dev libelf-dev`

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

USAGE: ebpf-bolt [-f FREQUENCY (max)] -p PID [duration (10s)]

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

## Showcases

### Profiling, perf record vs ebpf-bolt
Collecting the profile for Clang for 10 seconds with sampling frequency of 5000 Hz, average of 5 runs:
|           | Samples | User time | System time | CPU usage | Max RSS | File size |
| --------- | ------: | --------: | ----------: | --------: | ------: | --------: |
| perf record | 49304±25 | 0.40±0.02s | 0.27±0.01s | 5.4±0.5% | 96.8±0.2MB | 39.2MB |
| ebpf-bolt   | 49306±94 | 0.56±0.03s | 0.18±0.01s | 7.0±0.0% | 17.7±0.1MB |  3.4MB |
|             | **=**    | **+0.16s** | **-0.09s** | **+1.6pp** | **-81.7%** | **-91.3%** |

Summary:
 - Profiling with ebpf-bolt still has minimal overhead in terms of CPU usage, similar to `perf record`.
 - Peak memory usage during profiling is reduced significantly (96.8MB -> 17.7MB, -82%).
 - ebpf-bolt collects the same number of LBR samples, but produces a much
   smaller output file (39.2MB -> 3.4MB, -91%).
 - Slightly higher user time (+0.16s) in ebpf-bolt compared to perf is due to
   parsing and aggregating LBR samples, but these steps are eliminated from
   profile preprocessing in BOLT (-6.84s), which saves time overall.

### BOLT processing time, perf.data vs pre-aggregated profile
When perf profile is processed by BOLT, it's parsed using `perf script` commands.
No extra processing is needed for pre-aggregated profile produced by ebpf-bolt.

|                 | Pre-process profile | Process profile | Total rewrite time |
| --------------- | ------------------: | --------------: | -----------------: |
| perf.data       |               7.26s |           7.29s |            140.58s |
| pre-aggregated  |               0.42s |           6.38s |            132.43s |
|                 |          **-6.84s** |      **-0.91s** |         **-8.15s** |
