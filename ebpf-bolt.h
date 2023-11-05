/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EBPF_BOLT_H
#define __EBPF_BOLT_H

#define MAX_CPU_NR 128

#define MAX_NAME_LEN 128

struct preagg_entry_t {
  unsigned long long from;
  unsigned long long to;
  unsigned long long count;
};

#endif /* __EBPF_BOLT_H */