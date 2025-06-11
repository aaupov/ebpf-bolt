// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Based on runqlen(8) from BCC by Brendan Gregg.
// Based on runqlen from iovisor/BCC by Wenbo Zhang.
// Amir Ayupov

#include "ebpf-bolt.h"
#include "ebpf-bolt.skel.h"
#include <argp.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <unordered_map>
#include <signal.h>
#include <time.h>
#include <uapi/linux/perf_event.h>
#include <unistd.h>
#include <xxhash.h>
#include <string>
#include <fstream>
#include <sstream>
#include <elf.h>
#include <sys/stat.h>

struct env {
  time_t duration;
  bool max_freq;
  int freq;
  int pid;
  bool verbose;
} env = {.duration = 10, .max_freq = true, .freq = 99, .pid = -1, .verbose = 0};

static volatile bool exiting;

const char *argp_program_version = "ebpf-bolt 0.3";
const char *argp_program_bug_address =
    "https://github.com/aaupov/ebpf-bolt/issues";
const char argp_program_doc[] =
    "Collect pre-aggregated BOLT profile.\n\n"
    "USAGE: ebpf-bolt [-f FREQUENCY (max)] -p PID [duration (10s)]\n";

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "Sample on this PID only"},
    {"frequency", 'f', "FREQUENCY", 0,
     "Sample with a certain frequency, integer or `max'"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {},
};

int read_max_sample_rate() {
  int max_freq;
  int fd = open("/proc/sys/kernel/perf_event_max_sample_rate", O_RDONLY);
  fscanf(fdopen(fd, "r"), "%u", &max_freq);
  close(fd);
  return max_freq;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  int max_freq = read_max_sample_rate();

  static int pos_args;

  switch (key) {
  case 'h':
    argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
    break;
  case 'v':
    env.verbose = true;
    break;
  case 'p':
    errno = 0;
    env.pid = strtol(arg, NULL, 10);
    if (errno || env.pid <= 0) {
      fprintf(stderr, "Invalid PID: %s\n", arg);
      argp_usage(state);
    }
    break;
  case 'f': {
    errno = 0;
    if (strncmp(arg, "max", strlen("max")) == 0) {
      // default behavior, do nothing
    } else {
      env.max_freq = false;
      env.freq = strtol(arg, NULL, 10);
    }
    if (errno || env.freq <= 0 || env.freq > max_freq) {
      fprintf(stderr, "Invalid freq: %s", arg);
      if (env.freq > max_freq)
        fprintf(stderr, ": exceeds max_sample_rate %d", max_freq);
      fprintf(stderr, "\n");
      argp_usage(state);
    }
  } break;
  case ARGP_KEY_ARG:
    errno = 0;
    if (pos_args == 0) {
      env.duration = strtol(arg, NULL, 10);
      if (errno) {
        fprintf(stderr, "invalid internal\n");
        argp_usage(state);
      }
    } else {
      fprintf(stderr, "unrecognized positional argument: %s\n", arg);
      argp_usage(state);
    }
    pos_args++;
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  if (env.pid == -1) {
    fprintf(stderr, "Please specify PID\n");
    argp_usage(state);
  }
  if (env.max_freq) {
    env.freq = max_freq;
    if (env.verbose)
      fprintf(stderr, "Using max_sample_rate from /proc/sys: %d\n", env.freq);
  }
  return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
                                      struct bpf_link *links[]) {
  struct perf_event_attr attr = {
      .type = PERF_TYPE_HARDWARE,
      .config = PERF_COUNT_HW_CPU_CYCLES,
      .sample_freq = (unsigned)freq,
      .sample_type = PERF_SAMPLE_BRANCH_STACK,
      .freq = 1,
      .branch_sample_type = PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_ANY,
  };
  attr.size = sizeof(attr);
  int i, fd;

  for (i = 0; i < nr_cpus; i++) {
    fd = syscall(__NR_perf_event_open, &attr, env.pid, i, -1, 0);
    if (fd < 0) {
      /* Ignore CPU that is offline */
      if (errno == ENODEV)
        continue;
      fprintf(stderr, "failed to init perf sampling: %s\n", strerror(errno));
      return -1;
    }
    links[i] = bpf_program__attach_perf_event(prog, fd);
    if (!links[i]) {
      fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
      close(fd);
      return -1;
    }
  }

  return 0;
}

void cleanup_core_btf(struct bpf_object_open_opts *opts) {
  if (!opts)
    return;

  if (!opts->btf_custom_path)
    return;

  unlink(opts->btf_custom_path);
  free((void *)opts->btf_custom_path);
}

struct trace_t {
  unsigned long long branch, from, to;
  bool operator==(const trace_t &O) const = default;
};
struct counters_t {
  unsigned long long count{0}, mispred{0}, cycles{0};
};
struct trace_hash {
  size_t operator()(const trace_t &key) const {
    return XXH3_64bits(&key, sizeof(trace_t));
  }
};

typedef std::unordered_map<trace_t, counters_t, trace_hash> agg_map_t;
agg_map_t traces;

int handle_event(void *ctx, void *data, size_t data_sz) {
  agg_map_t &traces = *static_cast<agg_map_t *>(ctx);
  const struct event *e = reinterpret_cast<struct event *>(data);
  long entries = e->size / sizeof(event::entry_t);
  for (int i = 0; i < entries; ++i) {
    uint16_t cycles = 0;
    uint64_t ft_end = -1ULL;
    if (i + 1 != entries) {
      ft_end = e->entries[i + 1].from;
      cycles = e->entries[i + 1].flags.cycles;
    }
    trace_t trace{e->entries[i].from, e->entries[i].to, ft_end};
    counters_t &cnt = traces[trace];
    ++cnt.count;
    cnt.mispred += e->entries[i].flags.mispred;
    cnt.cycles += cycles;
  }
  return 0;
}

void print_aggregated(unsigned long base_addr) {
  fprintf(stderr, "%ld traces\n", traces.size());
  for (auto &&[key, val] : traces) {
    unsigned long long branch = key.branch - base_addr;
    unsigned long long from = key.from - base_addr;
    if (key.to == -1ULL)
      printf("B %llx %llx %llu %llu\n", branch, from, val.count, val.mispred);
    else {
      unsigned long long to = key.to - base_addr;
      printf("T %llx %llx %llx %llu\n", branch, from, to, val.count);
    }
    // cycles are not printed
  }
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG && !env.verbose)
    return 0;
  return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
  exiting = true;
}

static int64_t diff_s(const struct timespec &start,
                      const struct timespec &end) {
  time_t seconds = end.tv_sec - start.tv_sec;
  if (end.tv_nsec < start.tv_nsec)
    --seconds;
  return seconds;
}

unsigned long get_base_address(int pid) {
  std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
  std::ifstream maps_file(maps_path);
  if (!maps_file.is_open()) {
    fprintf(stderr, "Failed to open %s\n", maps_path.c_str());
    return 0;
  }
  std::string line;
  while (std::getline(maps_file, line)) {
    std::istringstream iss(line);
    std::string address_range, perms, offset, dev, inode, pathname;
    if (!(iss >> address_range >> perms >> offset >> dev >> inode))
      continue;
    std::getline(iss, pathname); // get the rest of the line
    // Look for the main executable mapping (r-xp and inode != 0)
    if (perms.find('x') != std::string::npos && inode != "0") {
      size_t dash = address_range.find('-');
      if (dash != std::string::npos) {
        std::string base_addr_str = address_range.substr(0, dash);
        return std::stoul(base_addr_str, nullptr, 16);
      }
    }
  }
  return 0;
}

bool is_pie_executable(int pid) {
  std::string exe_path = "/proc/" + std::to_string(pid) + "/exe";
  struct stat st;
  if (lstat(exe_path.c_str(), &st) == -1) {
    fprintf(stderr, "Failed to stat %s\n", exe_path.c_str());
    exit(1);
  }
  // Open the ELF file
  FILE *f = fopen(exe_path.c_str(), "rb");
  if (!f) {
    fprintf(stderr, "Failed to open %s\n", exe_path.c_str());
    exit(1);
  }
  unsigned char e_ident[EI_NIDENT];
  if (fread(e_ident, 1, EI_NIDENT, f) != EI_NIDENT) {
    fclose(f);
    fprintf(stderr, "Failed to read e_ident from %s\n", exe_path.c_str());
    exit(1);
  }
  if (e_ident[EI_CLASS] != ELFCLASS64) {
    fclose(f);
    fprintf(stderr, "Only ELF64 is supported (BOLT limitation)\n");
    exit(1);
  }
  fseek(f, 0, SEEK_SET);
  Elf64_Ehdr ehdr;
  if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
    fclose(f);
    fprintf(stderr, "Failed to read ehdr from %s\n", exe_path.c_str());
    exit(1);
  }
  if (ehdr.e_type != ET_DYN) {
    fclose(f);
    if (env.verbose)
      fprintf(stderr, "non-ET_DYN\n");
    return false;
  }

  // Find dynamic section
  fseek(f, ehdr.e_phoff, SEEK_SET);
  for (int i = 0; i < ehdr.e_phnum; ++i) {
    Elf64_Phdr phdr;
    if (fread(&phdr, 1, sizeof(phdr), f) != sizeof(phdr)) break;
    if (phdr.p_type != PT_DYNAMIC)
      continue;
    size_t dyn_count = phdr.p_filesz / sizeof(Elf64_Dyn);
    fseek(f, phdr.p_offset, SEEK_SET);
    for (size_t j = 0; j < dyn_count; ++j) {
      Elf64_Dyn dyn;
      if (fread(&dyn, 1, sizeof(dyn), f) != sizeof(dyn)) break;
      if (dyn.d_tag != DT_FLAGS_1)
        continue;
      if (dyn.d_un.d_val & DF_1_PIE) {
        fclose(f);
        if (env.verbose)
          fprintf(stderr, "DF_1_PIE\n");
        return true;
      } else {
        fclose(f);
        if (env.verbose)
          fprintf(stderr, "non-DF_1_PIE\n");
        return false;
      }
    }
  }
  // If ET_DYN but no DT_FLAGS_1, check executable bit
  if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
    fclose(f);
    if (env.verbose)
      fprintf(stderr, "ET_DYN executable with no DT_FLAGS_1\n");
    return true;
  }
  fclose(f);
  if (env.verbose)
    fprintf(stderr, "regular shared object\n");
  return false;
}

int main(int argc, char **argv) {
  int i;
  LIBBPF_OPTS(bpf_object_open_opts, open_opts);
  static const struct argp argp = {
      .options = opts,
      .parser = parse_arg,
      .doc = argp_program_doc,
  };
  struct bpf_link *links[MAX_CPU_NR] = {};
  struct ring_buffer *rb = NULL;

  struct ebpf_bolt_bpf *skel;
  int err = 0;
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  // PIE support: check if PIE and get base address if so
  bool is_pie = is_pie_executable(env.pid);
  unsigned long base_addr = 0;
  if (is_pie) {
    fprintf(stderr, "PIE executable\n");
    base_addr = get_base_address(env.pid);
    if (env.verbose)
      fprintf(stderr, "Base address for PID %d: 0x%lx\n", env.pid, base_addr);
  }

  nr_cpus = libbpf_num_possible_cpus();
  if (nr_cpus < 0) {
    fprintf(stderr, "failed to get # of possible cpus: '%s'!\n",
            strerror(-nr_cpus));
    return 1;
  }
  if (nr_cpus > MAX_CPU_NR) {
    fprintf(stderr, "the number of cpu cores is too big, please "
                    "increase MAX_CPU_NR's value and recompile");
    return 1;
  }

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  skel = ebpf_bolt_bpf__open_opts(&open_opts);
  if (!skel) {
    fprintf(stderr, "failed to open BPF object\n");
    return 1;
  }
  err = ebpf_bolt_bpf__load(skel);
  if (err) {
    fprintf(stderr, "failed to load BPF object: %d\n", err);
    goto cleanup;
  }

  err = open_and_attach_perf_event(env.freq, skel->progs.lbr_branches, links);
  if (err)
    goto cleanup;

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &traces,
                        NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  if (env.verbose)
    fprintf(stderr, "Sampling pid %d for %ld s... Hit Ctrl-C to end.\n",
            env.pid, env.duration);

  signal(SIGINT, sig_handler);

  struct timespec start_ts, curr_ts;
  clock_gettime(CLOCK_MONOTONIC, &start_ts);

  while (1) {
    err = ring_buffer__poll(rb, 1000 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    } else if (err < 0) {
      fprintf(stderr, "Error polling ring buffer: %s\n", strerror(-err));
      goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &curr_ts);
    if (diff_s(start_ts, curr_ts) >= env.duration)
      break;
    if (exiting)
      break;
  }
  // Read maps and print aggregated data
  print_aggregated(base_addr);
cleanup:
  for (i = 0; i < nr_cpus; i++)
    bpf_link__destroy(links[i]);
  ring_buffer__free(rb);
  ebpf_bolt_bpf__destroy(skel);
  cleanup_core_btf(&open_opts);

  return err;
}
