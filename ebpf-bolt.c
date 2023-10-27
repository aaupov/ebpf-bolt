#include <stdio.h>
#include <bpf/libbpf.h>
#include "ebpf-bolt.h"
#include "ebpf-bolt.skel.h"

int main() {
  struct ebpf_bolt_bpf *skel;
  int err = 0;
  skel = ebpf_bolt_bpf__open_and_load();
  if (!skel) {
    printf("Failed to open BPF object\n");
    return 1;
  }
  ebpf_bolt_bpf__destroy(skel);
  return -err;
}
