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

struct env {
  time_t duration;
  bool max_freq;
  int freq;
  int pid;
  bool verbose;
} env = {.duration = 10, .max_freq = true, .freq = 99, .pid = -1, .verbose = 0};

static volatile bool exiting;

const char *argp_program_version = "ebpf-bolt 0.2";
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

typedef std::pair<unsigned long long, unsigned long long> preagg_entry_key_t;
struct preagg_entry_val_t {
  unsigned long long count{0}, mispred{0};
};

struct preagg_entry_key_hash {
  size_t operator()(const preagg_entry_key_t &key) const {
    return XXH3_64bits(&key, sizeof(preagg_entry_key_t));
  }
};

typedef std::unordered_map<preagg_entry_key_t, preagg_entry_val_t,
                           preagg_entry_key_hash>
    preagg_map_t;

struct ctx_s {
  preagg_map_t branches;
  preagg_map_t traces;
  long events = 0;
};

int handle_event(void *ctx, void *data, size_t data_sz) {
  ctx_s *preagg_ctx = static_cast<ctx_s *>(ctx);
  ++preagg_ctx->events;
  const struct event *e = reinterpret_cast<struct event *>(data);
  long entries = e->size / sizeof(event::entry_t);
  for (int i = 0; i < entries; ++i) {
    preagg_entry_key_t key{e->entries[i].from, e->entries[i].to};
    preagg_entry_val_t &val = preagg_ctx->branches[key];
    ++val.count;
    if (e->entries[i].flags.mispred)
      ++val.mispred;
    if (i != entries - 1) {
      // LBR is a stack, so entries are in reverse
      preagg_entry_key_t trace_key{e->entries[i + 1].to, e->entries[i].from};
      ++preagg_ctx->traces[trace_key].count;
    }
  }
  return 0;
}

void print_aggregated(ctx_s &preagg_ctx) {
  fprintf(stderr, "%ld events\n", preagg_ctx.events);
  for (auto &&[key, val] : preagg_ctx.branches)
    printf("B %llx %llx %llu %llu\n", key.first, key.second, val.count,
           val.mispred);
  for (auto &&[key, val] : preagg_ctx.traces)
    printf("F %llx %llx %llu\n", key.first, key.second, val.count);
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

  ctx_s preagg_ctx;

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
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &preagg_ctx,
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
  print_aggregated(preagg_ctx);
cleanup:
  for (i = 0; i < nr_cpus; i++)
    bpf_link__destroy(links[i]);
  ring_buffer__free(rb);
  ebpf_bolt_bpf__destroy(skel);
  cleanup_core_btf(&open_opts);

  return err;
}
