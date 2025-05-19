#include <bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} __cgroup_filter_map SEC(".maps");

// This function will be injected into the `BEGIN` probe.
int __set_filtered_cgroup(u32 cgroup_id)
{
  u32 key = 0;
  bpf_map_update_elem(&__cgroup_filter_map, &key, &cgroup_id, BPF_ANY);
}

// This function will be injected into all relevant probes.
int __in_filtered_cgroup()
{
  return bpf_current_task_under_cgroup(&__cgroup_filter_map, 0);
}
