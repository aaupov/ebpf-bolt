// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Based on runqlen(8) from BCC by Brendan Gregg.
// Based on runqlen from iovisor/BCC by Wenbo Zhang.
// Amir Ayupov

#include <stdio.h>
#include <bpf/libbpf.h>
#include <uapi/linux/perf_event.h>
#include "ebpf-bolt.h"
#include "ebpf-bolt.skel.h"
#include <asm/unistd.h>
#include <argp.h>

struct env
{
	time_t duration;
	int freq;
	char *name;
	int pid;
} env = {
	.duration = 10,
	.freq = 99,
	.pid = -1,
	.name = NULL,
};

const char *argp_program_version = "ebpf-bolt 0.1";
const char *argp_program_bug_address =
	"https://github.com/aaupov/ebpf-bolt/issues";
const char argp_program_doc[] =
	"Collect pre-aggregated BOLT profile.\n"
	"\n"
	"USAGE: ebpf-bolt [--help] [-p PID | -n NAME] [-f FREQUENCY (99Hz)] [duration (10s)]\n"
	"\n";

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Sample on this PID only"},
	{"name", 'n', "NAME", 0, "Sample on this process name only"},
	{"frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key)
	{
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0)
		{
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'n':
		env.name = arg;
		break;
	case 'f':
		errno = 0;
		env.freq = strtol(arg, NULL, 10);
		if (errno || env.freq <= 0)
		{
			fprintf(stderr, "Invalid freq (in hz): %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0)
		{
			env.duration = strtol(arg, NULL, 10);
			if (errno)
			{
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		}
		else
		{
			fprintf(stderr,
					"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	if (env.pid == -1 && env.name == NULL)
	{
		fprintf(stderr, "Please specify either PID or name\n");
		argp_usage(state);
	}
	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.freq = 1,
		.sample_period = freq,
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
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

int main(int argc, char **argv)
{
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
	if (nr_cpus < 0)
	{
		printf("failed to get # of possible cpus: '%s'!\n",
			   strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR)
	{
		fprintf(stderr, "the number of cpu cores is too big, please "
						"increase MAX_CPU_NR's value and recompile");
		return 1;
	}

	skel = ebpf_bolt_bpf__open_opts(&open_opts);
	if (!skel)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}
	/* initialize global data (filtering options) */
	skel->rodata->pid = env.pid;
	err = ebpf_bolt_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}
	
	memcpy(env.name, skel->rodata->name, MAX_NAME_LEN);
	skel->rodata->name[strnlen(env.name, MAX_NAME_LEN)] = '\0';

	err = open_and_attach_perf_event(env.freq, skel->progs.lbr_branches, links);
	if (err)
		goto cleanup;

	while (1) {
		sleep(1);
		if (env.duration-- <= 0)
			break;
	}
	// Read maps and print aggregated data
cleanup:
	for (i = 0; i < nr_cpus; i++)
		bpf_link__destroy(links[i]);
	ebpf_bolt_bpf__destroy(skel);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
