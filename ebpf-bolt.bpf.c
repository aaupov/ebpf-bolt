#include "ebpf-bolt.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ENTRY_CNT 32

int pid = 0;
bool verbose = false;

static struct perf_branch_entry entries[ENTRY_CNT] SEC(".data.lbrs");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 1 << 20);
  __type(key, struct lbr_entry_key_t);
  __type(value, struct lbr_entry_val_t);
} agg_lbr_entries SEC(".maps");

SEC("perf_event")
int BPF_PROG(lbr_branches) {
  // filtering by pid
  int curr_pid = bpf_get_current_pid_tgid() >> 32;
  if (curr_pid != pid) // pid doesn't match
    return 0;          // exit normally

  if (verbose)
    bpf_printk("BPF triggered from PID %d", pid);

  long total_entries = bpf_get_branch_snapshot(entries, sizeof(entries), 0);
  total_entries /= sizeof(struct perf_branch_entry);
  if (verbose)
    bpf_printk("total_entries %d:", total_entries);

  struct lbr_entry_val_t zero = {};

  for (long i = 0; i < ENTRY_CNT; i++) {
    if (i >= total_entries)
      break;
    struct lbr_entry_key_t entry = {entries[i].from, entries[i].to};
    if (verbose)
      bpf_printk("entry %llx->%llx", entries[i].from, entries[i].to);
    // atomically increment the count of the entry
    struct lbr_entry_val_t *val = bpf_map_lookup_elem(&agg_lbr_entries, &entry);
    if (val == NULL) {
      if (bpf_map_update_elem(&agg_lbr_entries, &entry, &zero, BPF_ANY))
        return 1;
      val = bpf_map_lookup_elem(&agg_lbr_entries, &entry);
      if (val == NULL)
        return 1;
    }
    ++val->count;
    if (bpf_map_update_elem(&agg_lbr_entries, &entry, val, BPF_ANY))
      return 1; // return an error code
    if (verbose)
      bpf_printk("bumped count: %lld", val->count);
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
