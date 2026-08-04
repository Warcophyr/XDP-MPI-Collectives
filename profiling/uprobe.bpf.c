// uprobe.bpf.c
// #define BPF_NO_GLOBAL_DATA
// #include <linux/bpf.h>
// #include <linux/ptrace.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// One start timestamp per in-flight call, keyed by pid_tgid (thread id).
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);   // pid_tgid
  __type(value, __u64); // start time in ns
} start_times SEC(".maps");

SEC("uprobe")
int BPF_UPROBE(on_my_func_entry, int x) {
  __u64 id = bpf_get_current_pid_tgid();
  __u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &id, &ts, BPF_ANY);
  return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(on_my_func_ret, int ret) {
  __u64 id = bpf_get_current_pid_tgid();

  __u64 *start = bpf_map_lookup_elem(&start_times, &id);
  if (!start)
    return 0;

  __u64 delta = bpf_ktime_get_ns() - *start; // nanoseconds
  bpf_map_delete_elem(&start_times, &id);

  __u64 sec = delta / 1000000000ULL; // whole seconds
  __u64 usec =
      (delta % 1000000000ULL) / 1000ULL; // remaining microseconds (6 digits)

  bpf_printk("my_func latency: %llu.%06llu sec\n", sec, usec);
  return 0;
}