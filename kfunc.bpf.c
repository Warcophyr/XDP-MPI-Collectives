// do not change the order of the include
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <string.h>
#include <linux/if_xdp.h>
// #include "/usr/include/x86_64-linux-gnu/pci/types.h"

const int XDP_CLONE = 6;

// extern struct sk_buff *mlx5e_build_linear_skb(struct mlx5e_rq *rq, void *va,
//                                               __u32 frag_size, __u16
//                                               headroom,
//                                               __u32 cqe_bcnt,
//                                               __u32 metasize) __ksym;
// extern void bpf_clone(__u32 cqe_bcnt, __u32 metasize, __u16 headroom) __ksym;
// extern void bpf_clone(struct xdp_md *ctx, __u16 headroom) __ksym;
extern void bpf_clone(__u32 data, __u32 metasize, __u32 cqe_bcnt,
                      __u16 headroom) __ksym;

static __always_inline __u16 ip_checksum_xdp(struct iphdr *ip) {
  __u32 sum = 0;
  __u16 *data = (__u16 *)ip;

// IP header is guaranteed to be at least 20 bytes, so 10 16-bit words
#pragma unroll
  for (int i = 0; i < 10; i++) {
    if (i == 5)
      continue; // Skip checksum field
    sum += bpf_ntohs(data[i]);
  }

  // Add carry
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return bpf_htons(~sum);
}
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
int kfunc(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;
  // rx_headroom = mxbuf.xdp.data - mxbuf.xdp.data_hard_start;
  //     metasize = mxbuf.xdp.data - mxbuf.xdp.data_meta;
  //     cqe_bcnt = mxbuf.xdp.data_end - mxbuf.xdp.data;
  //     frag_size = MLX5_SKB_FRAG_SZ(rx_headroom + cqe_bcnt);
  //     skb = mlx5e_build_linear_skb(rq, va, frag_size, rx_headroom, cqe_bcnt,
  //                                  metasize);
  // __u32 data_end_u32;
  // __u32 data_meta_u32;
  // struct xdp_md ctxcpy = {0};
  // ctxcpy.data = ctx->data;
  // ctxcpy.data_end = ctx->data_end;
  // ctxcpy.data_meta = ctx->data_meta;
  // bpf_clone(ctx, XDP_PACKET_HEADROOM);
  // __u32 cqe_bcnt = (__u32)ctx->data_end - (__u32)ctx->data;
  // __u32 metasize = (__u32)ctx->data - (__u32)ctx->data_meta;
  // bpf_clone(cqe_bcnt, metasize, XDP_PACKET_HEADROOM);
  // __u32 data_u32 = (__u32)data;
  // __u32 data_end_u32 = (__u32)ctx->data_end;
  // __u32 data_meta_u32 = (__u32)ctx->data_meta;
  // bpf_printk("%d", ctx->data);
  // bpf_clone(ctx->data, ctx->data_end, ctx->data_meta, XDP_PACKET_HEADROOM);
  // bpf_clone(ctx->data, 0, 0, XDP_PACKET_HEADROOM);

  // Basic packet validation
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    // bpf_printk("XDP: Ethernet header validation failed\n");
    return XDP_PASS;
  }

  // Only process IP packets
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    // bpf_printk("XDP: Non-IP packet, passing through\n");
    return XDP_PASS;
  }

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    // bpf_printk("XDP: IP header validation failed\n");
    return XDP_PASS;
  }

  // Only process UDP packets
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  __u32 ip_hdr_len = iph->ihl * 4;
  struct udphdr *udph = (void *)iph + ip_hdr_len;
  if ((void *)(udph + 1) > data_end) {
    // bpf_printk("XDP: UDP header validation failed\n");
    return XDP_PASS;
  }
  // void *l4_hdr = (void *)iph + ip_hdr_len;
  // if (l4_hdr + sizeof(struct udphdr) > data_end)
  //   return XDP_PASS;
  // void *payload = l4_hdr + sizeof(udph);
  // if (payload + sizeof(__u32) <= data_end) {
  //   __u32 netval = *(__u32 *)payload;
  //   __u32 val = bpf_ntohl(netval);
  //   bpf_printk("val %x", val);
  //   // Modify value: make it positive (for example, flip sign or set abs())
  //   __u32 new_val = (__u32)(-((__s32)val)); // absolute value

  //   bpf_printk("new_val %x", new_val);
  //   // Write back in network order
  // }
  __u32 data_u32;
  if (ctx->data + sizeof(__u32) <= ctx->data_end) {

    __builtin_memcpy(&data_u32, data, sizeof(data_u32));
    __u32 cqe_bcnt = (__u32)ctx->data_end - (__u32)ctx->data;
    __u32 metasize = (__u32)ctx->data - (__u32)ctx->data_meta;
    // // bpf_printk("data: %u", data_u32);
    if (ctx->data < ctx->data_meta) {
      bpf_printk("copy packet");
      bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
                 "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
                 eth->h_source[0], eth->h_source[1], eth->h_source[2],
                 eth->h_source[3], eth->h_source[4], eth->h_source[5],
                 eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
                 eth->h_dest[4], eth->h_dest[5]);

      // __u8 src_mac[ETH_ALEN];
      // __u8 dst_mac[ETH_ALEN];
      // __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
      // __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
      // __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
      // __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);
      bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
                 "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
                 eth->h_source[0], eth->h_source[1], eth->h_source[2],
                 eth->h_source[3], eth->h_source[4], eth->h_source[5],
                 eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
                 eth->h_dest[4], eth->h_dest[5]);

      __u32 saddr = iph->saddr;
      __u32 daddr = iph->daddr;
      __sum16 check = iph->check;
      __be16 id = iph->id;
      __be16 frag_off = iph->frag_off;
      __sum16 check_udp = udph->check;

      bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
      bpf_printk("Received Destination IP: 0x%x", bpf_ntohl(iph->daddr));
      // bpf_printk("IP checksum: 0x%04x\n", __builtin_bswap16(check));
      // bpf_printk("IP ID: %u, Fragment offset + flags: 0x%x\n", id,
      // frag_off);

      // __u32 new_daddr = bpf_ntohl(saddr);
      // __u32 new_saddr = bpf_ntohl(daddr);
      // iph->saddr = bpf_htonl(new_saddr);
      // iph->daddr = bpf_htonl(new_daddr);
      bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
      bpf_printk("Received Destination IP: 0x%x", bpf_ntohl(iph->daddr));

      bpf_printk("UDP: sport=%d dport=%d len=%d\n", bpf_ntohs(udph->source),
                 bpf_ntohs(udph->dest), bpf_ntohs(udph->len));
      udph->dest = bpf_htons(5001);
      // udph->dest = 12346;
      // udph->check = 0;

      iph->check = ip_checksum_xdp(iph);
      bpf_printk("UDP: sport=%d dport=%d len=%d\n", bpf_ntohs(udph->source),
                 bpf_ntohs(udph->dest), bpf_ntohs(udph->len));

      void *l4_hdr = (void *)iph + ip_hdr_len;
      if (l4_hdr + sizeof(struct udphdr) > data_end)
        return XDP_PASS;
      void *payload = l4_hdr + sizeof(udph);
      if (payload + sizeof(__u32) <= data_end) {
        __u32 netval = *(__u32 *)payload;
        __u32 val = bpf_ntohl(netval);
        bpf_printk("val %x", val);
        // Modify value: make it positive (for example, flip sign or set
        // abs())
        __u32 new_val = 2; // absolute value
        *(__u32 *)payload = bpf_htonl(new_val);

        bpf_printk("new_val %x", new_val);
        // Write back in network order
        udph->check = 0;
        iph->check = ip_checksum_xdp(iph);
      }
      return XDP_PASS;
    }
    // bpf_clone(data_u32, metasize, cqe_bcnt, XDP_PACKET_HEADROOM);
    // bpf_clone(ctx, XDP_PACKET_HEADROOM);
  }
  // bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
  //            "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
  //            eth->h_source[0], eth->h_source[1], eth->h_source[2],
  //            eth->h_source[3], eth->h_source[4], eth->h_source[5],
  //            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
  //            eth->h_dest[4], eth->h_dest[5]);

  // __u8 src_mac[ETH_ALEN];
  // __u8 dst_mac[ETH_ALEN];
  // __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
  // __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
  // __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
  // __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);
  // bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
  //            "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
  //            eth->h_source[0], eth->h_source[1], eth->h_source[2],
  //            eth->h_source[3], eth->h_source[4], eth->h_source[5],
  //            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
  //            eth->h_dest[4], eth->h_dest[5]);

  // __u32 saddr = iph->saddr;
  // __u32 daddr = iph->daddr;
  // __sum16 check = iph->check;
  // __be16 id = iph->id;
  // __be16 frag_off = iph->frag_off;
  // __sum16 check_udp = udph->check;

  // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
  // bpf_printk("Received Destination IP: 0x%x", bpf_ntohl(iph->daddr));
  // // bpf_printk("IP checksum: 0x%04x\n", __builtin_bswap16(check));
  // // bpf_printk("IP ID: %u, Fragment offset + flags: 0x%x\n", id,
  // // frag_off);

  // __u32 new_daddr = bpf_ntohl(saddr);
  // __u32 new_saddr = bpf_ntohl(daddr);
  // iph->saddr = bpf_htonl(new_saddr);
  // iph->daddr = bpf_htonl(new_daddr);
  // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
  // bpf_printk("Received Destination IP: 0x%x", bpf_ntohl(iph->daddr));

  // bpf_printk("UDP: sport=%d dport=%d len=%d\n", bpf_ntohs(udph->source),
  //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));
  // // udph->dest = bpf_htons(12346);
  // // udph->dest = 12346;
  // // udph->check = 0;

  // iph->check = ip_checksum_xdp(iph);
  // bpf_printk("UDP: sport=%d dport=%d len=%d\n", bpf_ntohs(udph->source),
  //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));

  // void *l4_hdr = (void *)iph + ip_hdr_len;
  // if (l4_hdr + sizeof(struct udphdr) > data_end)
  //   return XDP_PASS;
  // void *payload = l4_hdr + sizeof(udph);
  // if (payload + sizeof(__u32) <= data_end) {
  //   __u32 netval = *(__u32 *)payload;
  //   __u32 val = bpf_ntohl(netval);
  //   bpf_printk("val %x", val);
  //   // Modify value: make it positive (for example, flip sign or set
  //   // abs())
  //   __u32 new_val = 2; // absolute value
  //   *(__u32 *)payload = bpf_htonl(new_val);

  //   bpf_printk("new_val %x", new_val);
  //   // Write back in network order
  //   udph->check = 0;
  //   iph->check = ip_checksum_xdp(iph);
  // }
  // return XDP_TX;
  // return XDP_PASS;
  return XDP_CLONE;
}

char LICENSE[] SEC("license") = "GPL";
