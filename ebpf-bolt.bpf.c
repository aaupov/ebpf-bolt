#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ebpf-bolt.h"

#define ENTRY_CNT 32

const volatile char name[MAX_NAME_LEN] = {0};
const volatile int pid = 0;

static struct perf_branch_entry entries[ENTRY_CNT] SEC(".data.lbrs");

SEC("perf_event")
int BPF_PROG(lbr_branches)
{
  long i;

  // bpf_get_current_pid_tgid: by pid
  // bpf_get_current_comm: by process name
  // bpf_get_current_task: 
  // bpf_read_branch_records
  // bpf_get_func_ip
  // bpf_task_pt_regs
  // bpf_find_vma
  long total_entries = bpf_get_branch_snapshot(entries, sizeof(entries), 0);
  total_entries /= sizeof(struct perf_branch_entry);

  for (i = 0; i < ENTRY_CNT; i++)
  {
    if (i >= total_entries)
      break;
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
