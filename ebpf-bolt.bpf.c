#include "ebpf-bolt.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024 /* 1 MB */);
} rb SEC(".maps");

SEC("perf_event")
int lbr_branches(void *ctx) {
  struct event *e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!e)
    return 0;

  long bytes_written = bpf_read_branch_records(
      ctx, e->entries, sizeof(struct perf_branch_entry) * ENTRY_CNT, 0);

  if (bytes_written < 0) {
    bpf_ringbuf_discard(e, 0);
    return -bytes_written;
  }
  e->size = bytes_written;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
