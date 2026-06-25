// kprobe.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);   // pid_tgid
  __type(value, __u64); // start time in ns
} start_times SEC(".maps");

// Only trace processes whose name is exactly "MPI".
// comm is the task name (TASK_COMM_LEN = 16, NUL-terminated).
static __always_inline int is_target_comm(void) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  return comm[0] == 'M' && comm[1] == 'P' && comm[2] == 'I' && comm[3] == '\0';
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg_enter) {
  if (!is_target_comm())
    return 0; // not ./MPI — ignore

  __u64 id = bpf_get_current_pid_tgid();
  __u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &id, &ts, BPF_ANY);
  return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(udp_recvmsg_exit, int ret) {
  __u64 id = bpf_get_current_pid_tgid();

  // Lookup fails for any process we didn't record on entry,
  // so non-MPI calls are filtered out here automatically.
  __u64 *start = bpf_map_lookup_elem(&start_times, &id);
  if (!start)
    return 0;

  __u64 delta = bpf_ktime_get_ns() - *start;
  bpf_map_delete_elem(&start_times, &id);

  __u64 sec = delta / 1000000000ULL;
  __u64 usec = (delta % 1000000000ULL) / 1000ULL;

  bpf_printk("MPI udp_recvmsg latency: %llu.%06llu sec, bytes=%d\n", sec, usec,
             ret);
  return 0;
}