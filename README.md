# ebpf-bolt: eBPF tool to collect BOLT profile
Collect and aggregate LBR samples using eBPF with minimal profiling overhead.

Output pre-aggregated BOLT profile suitable for optimization (same binary) or conversion to other profile formats (fdata or YAML) that tolerate binary differences.

This tool enables quicker profiling + optimization turnaround time thanks to processing LBR samples on the fly and producing pre-aggregated profile at the end of profiling step, ready to be directly consumed by BOLT. 

## Limitations
At the moment, this tool doesn't handle memory mappings, making it unsuitable for collecting profile for shared libraries and PIE executables.

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
Collecting the profile for Clang for 10 seconds with sampling frequency of 6000 Hz, average of 5 runs:
|           | Samples | User time | System time | CPU usage | Max RSS | File size |
| --------- | ------: | --------: | ----------: | --------: | ------: | --------: |
| perf record | 59133.2 |    0.40s |      0.27s |      5.0% | 104.5MB |      47MB |
| ebpf-bolt | 58806.6 |      0.36s |      0.22s |      5.4% |  14.7MB |     2.1MB |
|           | **-0.6%** | **-10.1%** | **-17.3%** | **+0.4pp** | **-85.9%** | **-95.5%** |

Summary: profiling with ebpf-bolt still has minimal overhead in terms of CPU usage, similar to `perf record`. 
Peak memory usage during profiling is reduced significantly (104.5MB -> 14.7MB, -85.9%).
ebpf-bolt collects a similar number of LBR samples, resulting in equivalent profile quantity and quality.

### BOLT processing time, perf.data vs pre-aggregated profile
When perf profile is processed by BOLT, it's parsed using `perf script` commands.
No extra processing is needed for pre-aggregated profile produced by ebpf-bolt.

|                 | Pre-process profile | Process profile | Total rewrite time |
| --------------- | ------------------: | --------------: | -----------------: |
| perf.data       |               7.26s |           7.29s |            140.58s |
| pre-aggregated  |               0.42s |           6.38s |            132.43s |
|                 |          **-94.2%** |      **-12.4%** |          **-5.8%** |
