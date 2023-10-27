#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ebpf-bolt.h"

#define ENTRY_CNT 32
static struct perf_branch_entry entries[ENTRY_CNT] SEC(".data.lbrs");

SEC("perf_event")
int BPF_PROG(lbr_branches) {
  long i;

  long total_entries = bpf_get_branch_snapshot(entries, sizeof(entries), 0);
  total_entries /= sizeof(struct perf_branch_entry);

  for (i = 0; i < ENTRY_CNT; i++) {
    if (i >= total_entries)
      break;
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
