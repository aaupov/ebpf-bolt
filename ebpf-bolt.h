/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EBPF_BOLT_H
#define __EBPF_BOLT_H

#define ENTRY_CNT 32
#define MAX_CPU_NR 128

struct branch_flags {
  union {
    unsigned long long value;
    struct {
      unsigned long long mispred : 1;
      unsigned long long predicted : 1;
      unsigned long long in_tx : 1;
      unsigned long long abort : 1;
      unsigned long long cycles : 16;
      unsigned long long type : 4;
      unsigned long long spec : 2;
      unsigned long long new_type : 4;
      unsigned long long priv : 3;
      unsigned long long reserved : 31;
    };
  };
};

struct event {
  struct entry_t {
    unsigned long long from, to;
    struct branch_flags flags;
  } entries[ENTRY_CNT];
  long size;
};

#endif /* __EBPF_BOLT_H */
