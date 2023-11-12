#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ebpf-bolt.h"

#define ENTRY_CNT 32

char name[MAX_NAME_LEN] = {0};
int name_len = 0;
int pid = 0;

static struct perf_branch_entry entries[ENTRY_CNT] SEC(".data.lbrs");

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 1 << 20);
  __type(key, struct lbr_entry_key_t);
  __type(value, struct lbr_entry_val_t);
} agg_lbr_entries SEC(".maps");

SEC("perf_event")
int BPF_PROG(lbr_branches)
{
  long i;
  if (name_len) { // filtering by process name
    char curr_name[MAX_NAME_LEN];
    if (bpf_get_current_comm(curr_name, MAX_NAME_LEN) != 0) // failed to get process name
      return 1; // return an error code
    if (bpf_strncmp(name, name_len, curr_name) != 0) // process name doesn't match
      return 0; // exit normally
    // otherwise continue to reading the entries
  } else if (pid) { // filtering by pid
    int curr_pid = bpf_get_current_pid_tgid() >> 32;
    if (curr_pid != pid) // pid doesn't match
      return 0; // exit normally
    // otherwise continue to reading the entries
  } else { // no filtering
    return 0; // exit normally
  }
  // bpf_get_current_pid_tgid: by pid
  // bpf_get_current_comm: by process name
  // bpf_get_current_task: 
  // bpf_read_branch_records
  // bpf_get_func_ip
  // bpf_task_pt_regs
  // bpf_find_vma
  long total_entries = bpf_get_branch_snapshot(entries, sizeof(entries), 0);
  total_entries /= sizeof(struct perf_branch_entry);

  struct lbr_entry_val_t zero = {};

  for (i = 0; i < ENTRY_CNT; i++)
  {
    if (i >= total_entries)
      break;
    struct lbr_entry_key_t entry = {entries[i].from, entries[i].to};
    // atomically increment the count of the entry
    struct lbr_entry_val_t *val = bpf_map_lookup_elem(&agg_lbr_entries, &entry);
    if (val == NULL)
    {
      if (bpf_map_update_elem(&agg_lbr_entries, &entry, &zero, BPF_ANY))
        return 1;
      val = bpf_map_lookup_elem(&agg_lbr_entries, &entry);
      if (val == NULL)
        return 1;
    }
    ++val->count;
    if (bpf_map_update_elem(&agg_lbr_entries, &entry, val, BPF_ANY))
      return 1; // return an error code
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
