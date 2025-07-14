// do not change the order of the include
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __type(key, __u32);
//     __type(value, long);
//     __uint(max_entries, 256);
// } rxcnt SEC(".maps");

SEC("xdp") int xdp_prog_simple(struct xdp_md *ctx) {
  // void *data_end = (void *)(long)ctx->data_end;
  // void *data = (void *)(long)ctx->data;
  // struct ethhdr *eth = data;
  // __u16 h_proto;
  // __u32 key = 0;
  // long *value;

  // if(data + sizeof(struct ethhdr) > data_end){
  //   return XDP_DROP;
  // }

  // h_proto = eth->h_proto;

  // if(h_proto == htons(ETH_P_IPV6)){
  //   value = bpf_map_lookup_elem(&rxcnt, &key);
  //   if(value){
  //     __sync_fetch_and_add(value, 1);
  //   }
  //   return XDP_DROP;
  // }

  bpf_printk("Hello from XDP kernel program!\n");
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
__u32 VERSION SEC("version") = 1;
