// do not change the order of the include
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <string.h>

/* returns true if packet was consumed by xdp */

// #include <linux/printk.h>

/**
 * Returns true if the packet was consumed (TX, REDIRECT or DROP/ABORT),
 * false if it should be passed up the regular stack.
 */
// bool generic_xdp_handle(struct net_device *dev, struct bpf_prog *prog,
//                         struct xdp_buff *xdp) {
//   __u32 act;
//   int err;

//   /* Run the XDP program in-kernel */
//   act = bpf_prog_run_xdp(prog, xdp);

//   switch (act) {
//   case XDP_PASS:
//     /* let the stack handle it */
//     return false;

//   case XDP_TX:
//     /* bounce back on the same device (zero-copy) */
//     if (unlikely(netdev_xdp_xmit(xdp, dev))) {
//       pr_warn("generic_xdp: XDP_TX failed\n");
//       goto xdp_abort;
//     }
//     return true;

//   case XDP_REDIRECT:
//     /* redirect to another interface or to an AF_XDP socket */
//     err = xdp_do_redirect_map(dev, xdp, prog);
//     if (unlikely(err)) {
//       pr_warn("generic_xdp: REDIRECT failed (%d)\n", err);
//       goto xdp_abort;
//     }
//     return true;

//   default:
//     /* invalid return from BPF program */
//     bpf_warn_invalid_xdp_action(dev, prog, act);
//     // fallthrough;
//     // break;

//   case XDP_ABORTED:
//   xdp_abort:
//     /* trace the exception, then drop */
//     trace_xdp_exception(dev, prog, act);
//     // fallthrough;
//   case XDP_DROP:
//     /* drop the packet */
//     return true;
//   }
// }
// Map definition

#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include <bpf/bpf_helpers.h> // for SEC(), bpf_*_map(), etc.

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP); // or BPF_MAP_TYPE_XSKMAP
  __uint(max_entries, 64);
  __type(key, __u32);
  __type(value, __u32);
} xdp_redirect_map SEC(".maps");

typedef struct packet_info {
  __u32 ingress_ifindex;
  __u8 eth_hdr[14]; // Ethernet header
  __u8 ip_hdr[20];  // IPv4 header (no options)
  __u8 udp_hdr[8];  // UDP header
  __u32 total_len;  // e.g. ntohs(ip->tot_len)
  __u32 processed;  // Flag to prevent reprocessing
} packet_info;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1024);
  __type(value, packet_info);
  __type(key, __u32);
} info_packet_arr SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  __u32 idx = 0 /* map key—for example, metadata or hardcoded queue*/;
  int ret;

  /* 1) Clone & redirect the packet into `xdp_redirect_map[idx]` */
  ret = bpf_redirect_map(&xdp_redirect_map, idx, BPF_F_CLONE);
  if (ret < 0) {
    bpf_printk("noting found");
    return XDP_ABORTED; /* clone+redirect failed */
  }

  /* 2) Now decide what to do with the original: here we bounce it back */
  return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
