// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Based on runqlen(8) from BCC by Brendan Gregg.
// Based on runqlen from iovisor/BCC by Wenbo Zhang.
// Amir Ayupov

#include "ebpf-bolt.h"
#include "ebpf-bolt.skel.h"
#include <argp.h>
#include <asm/unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <uapi/linux/perf_event.h>
#include <unistd.h>

struct env {
  time_t duration;
  int freq;
  int pid;
  bool verbose;
} env = {.duration = 10, .freq = 99, .pid = -1, .verbose = 0};

static volatile bool exiting;

const char *argp_program_version = "ebpf-bolt 0.1";
const char *argp_program_bug_address =
    "https://github.com/aaupov/ebpf-bolt/issues";
const char argp_program_doc[] =
    "Collect pre-aggregated BOLT profile.\n\n"
    "USAGE: ebpf-bolt [-f FREQUENCY (99Hz)] -p PID [duration (10s)]\n";

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "Sample on this PID only"},
    {"frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
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
  case 'f':
    errno = 0;
    env.freq = strtol(arg, NULL, 10);
    if (errno || env.freq <= 0) {
      fprintf(stderr, "Invalid freq (in hz): %s\n", arg);
      argp_usage(state);
    }
    break;
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
    fprintf(stderr, "Please specify either PID\n");
    argp_usage(state);
  }
  return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
                                      struct bpf_link *links[]) {
  struct perf_event_attr attr = {
      .type = PERF_TYPE_HARDWARE,
      .config = PERF_COUNT_HW_CPU_CYCLES,
      .sample_freq = freq,
      .freq = 1,
      .branch_sample_type = PERF_SAMPLE_BRANCH_USER,
  };
  int i, fd;

  for (i = 0; i < nr_cpus; i++) {
    fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
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

static void walk_hash_elements(int map_fd, int nr_cpus) {
  struct lbr_entry_key_t *cur_key = NULL;
  struct lbr_entry_key_t next_key;
  struct lbr_entry_val_t *values = (struct lbr_entry_val_t *)malloc(
      sizeof(struct lbr_entry_val_t) * nr_cpus);
  int err;

  for (;;) {
    err = bpf_map_get_next_key(map_fd, cur_key, &next_key);
    if (err)
      break;

    bpf_map_lookup_elem(map_fd, &next_key, values);
    cur_key = &next_key;
    unsigned long long count = 0;
    for (int i = 0; i < nr_cpus; ++i)
      count += values[i].count;
    printf("B %llx %llx %llu 0\n", cur_key->from, cur_key->to, count);
  }
  free(values);
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

int main(int argc, char **argv) {
  int i;
  LIBBPF_OPTS(bpf_object_open_opts, open_opts);
  static const struct argp argp = {
      .options = opts,
      .parser = parse_arg,
      .doc = argp_program_doc,
  };
  struct bpf_link *links[MAX_CPU_NR] = {};

  struct ebpf_bolt_bpf *skel;
  int err = 0;
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  nr_cpus = libbpf_num_possible_cpus();
  if (nr_cpus < 0) {
    printf("failed to get # of possible cpus: '%s'!\n", strerror(-nr_cpus));
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
  /* initialize global data (filtering options) */
  skel->bss->pid = env.pid;
  err = ebpf_bolt_bpf__load(skel);
  if (err) {
    fprintf(stderr, "failed to load BPF object: %d\n", err);
    goto cleanup;
  }

  err = open_and_attach_perf_event(env.freq, skel->progs.lbr_branches, links);
  if (err)
    goto cleanup;

  if (env.verbose)
    fprintf(stderr, "Sampling pid %d for %ld s... Hit Ctrl-C to end.\n",
            env.pid, env.duration);

  signal(SIGINT, sig_handler);

  while (1) {
    sleep(1);
    if (exiting || env.duration-- <= 0)
      break;
  }
  // Read maps and print aggregated data
  walk_hash_elements(bpf_map__fd(skel->maps.agg_lbr_entries), nr_cpus);
cleanup:
  for (i = 0; i < nr_cpus; i++)
    bpf_link__destroy(links[i]);
  ebpf_bolt_bpf__destroy(skel);
  cleanup_core_btf(&open_opts);

  return err != 0;
}
