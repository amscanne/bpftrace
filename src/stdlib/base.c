#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

extern struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;
extern long int bpf_task_under_cgroup(struct task_struct *task,
                                      struct cgroup *ancestor) __ksym;

// This function will be injected into all relevant probes.
int __in_cgroup(uint64_t cgroup_id)
{
  struct cgroup *grp = bpf_cgroup_from_id(cgroup_id);
  if (!grp) {
    return 0;
  }
  int rval = bpf_task_under_cgroup(bpf_get_current_task_btf(), grp);
  bpf_cgroup_release(grp);
  return rval;
}
