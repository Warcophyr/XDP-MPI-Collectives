// do not change the order of the include
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifdef AXDP_INLINE
#include "axdp_tx.h"
#endif

#ifdef DEBUG
#define bpf_printk(fmt, ...) \
  ({ \
    char ____fmt[] = fmt; \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })
#else
#define bpf_printk(fmt, ...) \
  do { \ } while (0)
#endif

#define __XDP_CLONE_PASS 5
#define __XDP_CLONE_TX 6
#define __XDP_CLONE_REDIRECT 7
#define XDP_CLONE_PASS(num_copy)                                               \
  (((int)(num_copy) << 5) | (int)__XDP_CLONE_PASS)
#define XDP_CLONE_TX(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_TX)
#define XDP_CLONE_REDIRECT(num_copy)                                           \
  (((int)(num_copy) << 5) | (int)__XDP_CLONE_REDIRECT)

typedef enum MPI_Datatype {
  MPI_ACK,
  MPI_NACK,
  MPI_CHAR,
  MPI_SIGNED_CHAR,
  MPI_UNSIGNED_CHAR,
  MPI_SHORT,
  MPI_UNSIGNED_SHORT,
  MPI_INT,
  MPI_UNSIGNED,
  MPI_LONG,
  MPI_UNSIGNED_LONG,
  MPI_LONG_LONG,
  MPI_UNSIGNED_LONG_LONG,
  MPI_FLOAT,
  MPI_DOUBLE,
  MPI_LONG_DOUBLE,
  MPI_C_BOOL,
  MPI_WCHAR
} MPI_Datatype;

typedef enum MPI_Collective {
  MPI_SEND,
  MPI_BCAST,
  MPI_BCAST_LINEAR,
  MPI_BCAST_RING,
  MPI_REDUCE,
  MPI_SHATTER,
  MPI_GATHER,
  MPI_SHATTERV,
  MPI_GATHERV
} MPI_Collective;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);   // array index
  __type(value, __u64); // element stored at that index
} num_process SEC(".maps");

typedef struct socket_id {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol;
} __attribute__((packed)) socket_id;

typedef struct tuple_process {
  __u32 src_procc;
  __u32 dst_procc;
} tuple_process;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, socket_id);
  __type(value, tuple_process);
} address_to_proc SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, tuple_process);
  __type(value, socket_id);
} proc_to_address SEC(".maps");

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

/* How a copy is steered to its next hop.
 *
 * A hop rewrites the same 58 bytes at the front of the frame either way: the
 * two MACs, the next hop's 5-tuple in the IP and UDP headers, and the src/dst
 * ranks in the MPI header -- which is why it reaches 58 and not 42, those two
 * fields sitting at offsets 50 and 54. What differs is who writes them.
 */
#define AXDP_MPI_FIELDS 16 /* magic + root + src + dst */

#ifndef AXDP_INLINE

/* In software, in place, as XDP has always done it. */
static __always_inline int forward_copy(struct xdp_md *ctx, struct ethhdr *eth,
                                        struct iphdr *iph,
                                        struct udphdr *udph, void *payload,
                                        int from, int to,
                                        const socket_id *info) {
  void *src_payload = (char *)payload + (sizeof(char) * 4) + sizeof(int);
  void *dst_payload = (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 2);
  int from_net = bpf_htonl(from);
  int to_net = bpf_htonl(to);
  __u8 src_mac[ETH_ALEN];
  __u8 dst_mac[ETH_ALEN];

  __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
  __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
  __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);

  __builtin_memcpy(src_payload, &from_net, sizeof(int));
  __builtin_memcpy(dst_payload, &to_net, sizeof(int));

  udph->source = bpf_htons(info->src_port);
  udph->dest = bpf_htons(info->dst_port);
  udph->check = 0;

  iph->saddr = info->src_ip;
  iph->daddr = info->dst_ip;
  iph->check = ip_checksum_xdp(iph);

  return XDP_TX;
}

#else /* AXDP_INLINE */

/* Total inline header, and the metadata needed to hold it and the descriptor. */
#define AXDP_HDR_LEN                                                           \
  (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + AXDP_MPI_FIELDS)
#define AXDP_META_NEED (((AXDP_TX_DESC_LEN + AXDP_HDR_LEN) + 3) & ~3U)

/* In hardware. The header is built in the copy's own metadata and handed to
 * the NIC as the WQE inline header; the NIC puts it on the wire in place of
 * the packet's first AXDP_HDR_LEN bytes, which the driver leaves out of the
 * DMA (AXDP_TX_REPLACE). The packet is never written to, so the frame keeps
 * its length and no checksum is folded over packet memory.
 */
static __always_inline int forward_copy(struct xdp_md *ctx, struct ethhdr *eth,
                                        struct iphdr *iph,
                                        struct udphdr *udph, void *payload,
                                        int from, int to,
                                        const socket_id *info) {
  /* Separately aligned locals, patched here and concatenated into the
   * metadata below. One overlaid byte buffer would be simpler to write, but it
   * puts the IP header at an odd offset on the stack and the verifier rejects
   * the misaligned access.
   */
  struct ethhdr h_eth;
  struct iphdr h_ip;
  struct udphdr h_udp;
  __u32 h_mpi[AXDP_MPI_FIELDS / sizeof(__u32)];
  __u8 mac[ETH_ALEN];
  void *meta;

  /* The 58 bytes assume the canonical header: no IP options. */
  if (iph->ihl != 5)
    return XDP_PASS;
  if ((char *)payload + AXDP_MPI_FIELDS > (char *)(long)ctx->data_end)
    return XDP_PASS;

  __builtin_memcpy(&h_eth, eth, sizeof(h_eth));
  __builtin_memcpy(&h_ip, iph, sizeof(h_ip));
  __builtin_memcpy(&h_udp, udph, sizeof(h_udp));
  __builtin_memcpy(h_mpi, payload, sizeof(h_mpi));

  __builtin_memcpy(mac, h_eth.h_source, ETH_ALEN);
  __builtin_memcpy(h_eth.h_source, h_eth.h_dest, ETH_ALEN);
  __builtin_memcpy(h_eth.h_dest, mac, ETH_ALEN);

  h_udp.source = bpf_htons(info->src_port);
  h_udp.dest = bpf_htons(info->dst_port);
  h_udp.check = 0;

  h_ip.saddr = info->src_ip;
  h_ip.daddr = info->dst_ip;
  h_ip.check = ip_checksum_xdp(&h_ip);

  h_mpi[2] = bpf_htonl(from); /* src rank */
  h_mpi[3] = bpf_htonl(to);   /* dst rank */

  /* Grow the metadata to hold the descriptor and the header. The driver put
   * AXDP_CLONE_META_SIZE bytes in front of a copy holding its index; that has
   * already been read, and nothing else in there needs to survive.
   */
  if (bpf_xdp_adjust_meta(ctx,
                          -(int)(AXDP_META_NEED - AXDP_CLONE_META_SIZE)) < 0)
    return XDP_PASS;

  meta = (void *)(long)ctx->data_meta;
  if ((char *)meta + AXDP_META_NEED > (char *)(long)ctx->data)
    return XDP_PASS;

  meta = (char *)meta + AXDP_TX_DESC_LEN;
  __builtin_memcpy(meta, &h_eth, sizeof(h_eth));
  __builtin_memcpy((char *)meta + ETH_HLEN, &h_ip, sizeof(h_ip));
  __builtin_memcpy((char *)meta + ETH_HLEN + sizeof(struct iphdr), &h_udp,
                   sizeof(h_udp));
  __builtin_memcpy((char *)meta + ETH_HLEN + sizeof(struct iphdr) +
                       sizeof(struct udphdr),
                   h_mpi, sizeof(h_mpi));

  if (axdp_stamp_tx_replace(ctx, 0, AXDP_HDR_LEN) < 0)
    return XDP_PASS;

  return XDP_TX;
}

#endif /* AXDP_INLINE */

static __always_inline int parse_ip_packet(struct xdp_md *ctx,
                                           struct ethhdr **out_eth,
                                           struct iphdr **out_iph,
                                           struct udphdr **out_udph) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    // bpf_printk("TC: Ethernet header validation failed\n");
    return XDP_PASS;
  }

  // Only process IP packets. Pass others through safely.
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    // //bpf_printk("TC: Non-IP packet, passing through\n");
    return XDP_PASS; // FIXED: XDP_PASS allows the packet to continue
  }

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    // bpf_printk("TC: IP header validation failed\n");
    return XDP_PASS;
  }

  // eBPF Verifier requirement: ensure the IP header length is at least
  // 5 words (20 bytes) to prevent invalid offsets.
  if (iph->ihl < 5) {
    // bpf_printk("TC: Invalid IP header length\n");
    return XDP_PASS;
  }

  // Only process UDP packets. Pass others through safely.
  if (iph->protocol != IPPROTO_UDP) {
    // //bpf_printk("TC: Non-UDP packet, passing through\n");
    return XDP_PASS;
  }

  __u32 ip_hdr_len = iph->ihl * 4;
  struct udphdr *udph = (void *)iph + ip_hdr_len;
  if ((void *)(udph + 1) > data_end) {
    // //bpf_printk("XDP: UDP header validation failed\n");
    return XDP_PASS;
  }

  // Successfully parsed. Assign the IP header pointer back to the caller.
  if (out_eth && out_iph && out_udph) {
    *out_eth = eth;
    *out_iph = iph;
    *out_udph = udph;
  }

  return -1;
}

// int __src_host = 0;
__u32 count_pass = 0;
__u32 count_tx = 0;
__u64 start_time = 0;

static __always_inline int handle_clone(struct xdp_md *ctx, struct ethhdr *eth,
                                        struct iphdr *iph,
                                        struct udphdr *udph) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  if (!iph) {
    // bpf_printk("TC: IP header is NULL in handle_clone\n");
    return XDP_PASS;
  }
  udph = (void *)iph + iph->ihl * 4;
  if (udph + 1 > (void *)(long)ctx->data_end) {
    // bpf_printk("TC: UDP header validation failed\n");
    return XDP_PASS;
  }

  void *payload = (void *)udph + sizeof(*udph);

  const int num_char = 4;
  const int needed = (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2) + sizeof(unsigned long) +
                     sizeof(unsigned long);
  if (payload + needed > ctx->data_end)
    return XDP_PASS; /* not enough payload */

  char mpi_header[4] = {'a', 'a', 'a', 'a'};
#pragma unroll
  for (int i = 0; i < num_char; i++) {
    __builtin_memcpy(&mpi_header[i], payload + i * sizeof(char), sizeof(char));
  }

  // //bpf_printk("udp first4: %c %c %c %c\n", mpi_header[0], mpi_header[1],
  //            mpi_header[2], mpi_header[3]);
  if (mpi_header[0] != 'M' && mpi_header[1] != 'P' && mpi_header[2] != 'I' &&
      mpi_header[3] != '\0') {
    return XDP_PASS;
  }

  int root;
  void *root_payload = (char *)payload + (sizeof(char) * 4);
  __builtin_memcpy(&root, root_payload, sizeof(int));
  int root_host = bpf_ntohl(root);

  int src;
  void *src_payload = (char *)payload + (sizeof(char) * 4) + sizeof(int);
  __builtin_memcpy(&src, src_payload, sizeof(int));
  int src_host = bpf_ntohl(src);
  // __src_host = src_host;

  int dst;
  void *dst_payload = (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 2);
  __builtin_memcpy(&dst, dst_payload, sizeof(int));
  int dst_host = bpf_ntohl(dst);

  MPI_Collective opcode;
  void *opcode_payload =
      (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 3);
  __builtin_memcpy(&opcode, opcode_payload, sizeof(MPI_Collective));
  MPI_Collective opcode_host = bpf_ntohl(opcode);

  MPI_Datatype datatype;
  void *datatype_payload = (char *)payload + (sizeof(char) * 4) +
                           (sizeof(int) * 3) + sizeof(MPI_Collective);
  __builtin_memcpy(&datatype, datatype_payload, sizeof(MPI_Datatype));
  MPI_Datatype datatype_host = bpf_ntohl(datatype);

  int len;
  void *len_payload = (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 3) +
                      sizeof(MPI_Collective) + sizeof(MPI_Datatype);
  __builtin_memcpy(&len, len_payload, sizeof(int));
  int len_host = bpf_ntohl(len);

  int tag;
  void *tag_payload = (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 3) +
                      sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                      sizeof(int);
  __builtin_memcpy(&tag, tag_payload, sizeof(int));
  int tag_host = bpf_ntohl(tag);

  unsigned long seq;
  void *seq_payload = (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 3) +
                      sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                      (sizeof(int) * 2);
  __builtin_memcpy(&seq, seq_payload, sizeof(unsigned long));
  unsigned long seq_host = bpf_ntohl(seq);

  unsigned long clock;
  void *clock_payload = (char *)payload + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective) +
                        sizeof(MPI_Datatype) + (sizeof(int) * 2) +
                        sizeof(unsigned long);
  __builtin_memcpy(&clock, clock_payload, sizeof(unsigned long));
  unsigned long clock_host = bpf_ntohl(clock);
  switch (opcode_host) {
  case MPI_SEND:
    return XDP_PASS;
    break;
  case MPI_BCAST: {
    if (root_host == dst_host) {
      return XDP_PASS;
    }
    if (ctx->data + sizeof(__u32) <= ctx->data_end) {
      if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
        int iter_copy = 0;
        __builtin_memcpy(&iter_copy, data_meta, sizeof(iter_copy));
        // //bpf_printk("CASE 2 iter: %d root: %d, src: %d, dst: %d, opcode: %d,
        // "
        //            "datatype: %d, len : "
        //            "%d, tag: %d seq: %lu clock: %lu",
        //            iter_copy, root_host, src_host, dst_host, opcode_host,
        //            datatype_host, len_host, tag_host, seq_host,
        //            clock_host);
        // //bpf_printk("old_src_ip %lu", bpf_ntohl(iph->saddr));
        int key_num_process = 0;
        int *size_ptr = bpf_map_lookup_elem(&num_process, &key_num_process);
        if (size_ptr) {
          int size = *size_ptr;
          if (iter_copy == 0) {
            return XDP_CLONE_PASS(2);
          }
          // //bpf_printk("size: %d", *size);
          // int next = (int)(((unsigned)(dst_host + 1)) %
          // ((unsigned)(*size)));
          // if (src_host > (int)((unsigned int)size / 2)) {
          //   return XDP_PASS;
          // }
          int next = (2 * src_host) + 2;
          // (int)(((unsigned)((2 * src_host) + 2)) % ((unsigned)(size)));
          if (next >= size) {
            // //bpf_printk("hi 2");
            return XDP_PASS;
          }
          tuple_process inter_dest = {0};
          inter_dest.src_procc = src_host;
          inter_dest.dst_procc = next;
          socket_id *info_forwad_next =
              bpf_map_lookup_elem(&proc_to_address, &inter_dest);
          if (info_forwad_next) {
            // __u8 src_mac[ETH_ALEN];
            // __u8 dst_mac[ETH_ALEN];
            // __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
            // __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
            // __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
            // __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);

            int dst_net = bpf_htonl(src_host);
            int next_net = bpf_htonl(next);
            __builtin_memcpy(src_payload, &dst_net, sizeof(int));
            __builtin_memcpy(dst_payload, &next_net, sizeof(int));

            udph->source = bpf_htons(info_forwad_next->src_port);
            udph->dest = bpf_htons(info_forwad_next->dst_port);
            udph->check = 0;

            iph->saddr = info_forwad_next->src_ip;
            iph->daddr = info_forwad_next->dst_ip;
            iph->check = ip_checksum_xdp(iph);
            // //bpf_printk("new_src: %d next: %d src_port: %d dst_port: %d "
            //            "src_ip: %ld dst_ip: %ld",
            //            src_host, next, info_forwad_next->src_port,
            //            info_forwad_next->dst_port,
            //            info_forwad_next->src_ip, info_forwad_next->dst_ip);
            // //bpf_printk("src_ip: %lu", bpf_ntohl(iph->saddr));
            // //bpf_printk("dst_ip: %lu", bpf_ntohl(iph->daddr));
            // __src = 0;
            return XDP_TX;
          }
        }
      } else {
        return XDP_PASS;
      }
    }
    return XDP_PASS;
  } break;
  case MPI_BCAST_RING: {
    if (root_host == dst_host) {
      bpf_printk("ho finito in clone");
      return XDP_PASS;
    }
    if (ctx->data + sizeof(__u32) <= ctx->data_end) {
      if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
        int iter_copy = 0;
        __builtin_memcpy(&iter_copy, data_meta, sizeof(iter_copy));
        // //bpf_printk("num_copy: %d", num_copy);
        int key_num_process = 0;
        int *size_ptr = bpf_map_lookup_elem(&num_process, &key_num_process);
        if (size_ptr) {
          int size = *size_ptr;
          int next =
              (int)(((unsigned)((dst_host) + iter_copy)) % ((unsigned)(size)));
          if (root_host == next) {
            return XDP_PASS;
          }
          tuple_process inter_dest = {0};
          inter_dest.src_procc = dst_host;
          inter_dest.dst_procc = next;
          socket_id *info_forwad_next =
              bpf_map_lookup_elem(&proc_to_address, &inter_dest);
          if (info_forwad_next) {
            count_tx++;
            return forward_copy(ctx, eth, iph, udph, payload, dst_host,
                                next, info_forwad_next);
          }
        }
      } else {
        return XDP_PASS;
      }
    }
    return XDP_PASS;
  } break;
  case MPI_BCAST_LINEAR: {
    if (root_host == dst_host) {
      return XDP_PASS;
    }
    if (ctx->data + sizeof(__u32) <= ctx->data_end) {
      if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
        int iter_copy = 0;
        __builtin_memcpy(&iter_copy, data_meta, sizeof(iter_copy));
        // bpf_printk("num_copy: %d", iter_copy);
        int key_num_process = 0;
        int *size_ptr = bpf_map_lookup_elem(&num_process, &key_num_process);
        if (size_ptr) {
          int size = *size_ptr;
          int next =
              (int)(((unsigned)((dst_host) + iter_copy)) % ((unsigned)(size)));
          if (root_host == next) {
            return XDP_PASS;
          }
          // bpf_printk("dst_host: %d next: %d", dst_host, next);
          tuple_process inter_dest = {0};
          inter_dest.src_procc = dst_host;
          inter_dest.dst_procc = next;
          socket_id *info_forwad_next =
              bpf_map_lookup_elem(&proc_to_address, &inter_dest);
          if (info_forwad_next) {
            count_tx++;
            return forward_copy(ctx, eth, iph, udph, payload, dst_host,
                                next, info_forwad_next);
          }
        }
      } else {
        return XDP_PASS;
      }
    }
    return XDP_PASS;
  } break;
  case MPI_REDUCE: {
    return XDP_PASS;
  } break;
  default:
    return XDP_PASS;
    break;
  }
}

static __always_inline int handle_original(struct xdp_md *ctx,
                                           struct ethhdr *eth,
                                           struct iphdr *iph,
                                           struct udphdr *udph) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  if (!iph) {
    // bpf_printk("TC: IP header is NULL in handle_clone\n");
    return XDP_PASS;
  }
  udph = (void *)iph + iph->ihl * 4;
  if (udph + 1 > (void *)(long)ctx->data_end) {
    // bpf_printk("TC: UDP header validation failed\n");
    return XDP_PASS;
  }

  void *payload = (void *)udph + sizeof(*udph);

  const int num_char = 4;
  const int needed = (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2) + sizeof(unsigned long) +
                     sizeof(unsigned long);
  if (payload + needed > ctx->data_end)
    return XDP_PASS; /* not enough payload */

  char mpi_header[4] = {'a', 'a', 'a', 'a'};
#pragma unroll
  for (int i = 0; i < num_char; i++) {
    __builtin_memcpy(&mpi_header[i], payload + i * sizeof(char), sizeof(char));
  }

  // //bpf_printk("udp first4: %c %c %c %c\n", mpi_header[0], mpi_header[1],
  //            mpi_header[2], mpi_header[3]);
  if (mpi_header[0] != 'M' && mpi_header[1] != 'P' && mpi_header[2] != 'I' &&
      mpi_header[3] != '\0') {
    return XDP_PASS;
  }

  int root;
  void *root_payload = (char *)payload + (sizeof(char) * 4);
  __builtin_memcpy(&root, root_payload, sizeof(int));
  int root_host = bpf_ntohl(root);

  int src;
  void *src_payload = (char *)payload + (sizeof(char) * 4) + sizeof(int);
  __builtin_memcpy(&src, src_payload, sizeof(int));
  int src_host = bpf_ntohl(src);
  // __src_host = src_host;

  int dst;
  void *dst_payload = (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 2);
  __builtin_memcpy(&dst, dst_payload, sizeof(int));
  int dst_host = bpf_ntohl(dst);

  MPI_Collective opcode;
  void *opcode_payload =
      (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 3);
  __builtin_memcpy(&opcode, opcode_payload, sizeof(MPI_Collective));
  MPI_Collective opcode_host = bpf_ntohl(opcode);

  MPI_Datatype datatype;
  void *datatype_payload = (char *)payload + (sizeof(char) * 4) +
                           (sizeof(int) * 3) + sizeof(MPI_Collective);
  __builtin_memcpy(&datatype, datatype_payload, sizeof(MPI_Datatype));
  MPI_Datatype datatype_host = bpf_ntohl(datatype);

  int len;
  void *len_payload = (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 3) +
                      sizeof(MPI_Collective) + sizeof(MPI_Datatype);
  __builtin_memcpy(&len, len_payload, sizeof(int));
  int len_host = bpf_ntohl(len);

  int tag;
  void *tag_payload = (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 3) +
                      sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                      sizeof(int);
  __builtin_memcpy(&tag, tag_payload, sizeof(int));
  int tag_host = bpf_ntohl(tag);

  unsigned long seq;
  void *seq_payload = (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 3) +
                      sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                      (sizeof(int) * 2);
  __builtin_memcpy(&seq, seq_payload, sizeof(unsigned long));
  unsigned long seq_host = bpf_ntohl(seq);

  unsigned long clock;
  void *clock_payload = (char *)payload + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective) +
                        sizeof(MPI_Datatype) + (sizeof(int) * 2) +
                        sizeof(unsigned long);
  __builtin_memcpy(&clock, clock_payload, sizeof(unsigned long));
  unsigned long clock_host = bpf_ntohl(clock);

  int key_num_process = 0;
  int *size_ptr = bpf_map_lookup_elem(&num_process, &key_num_process);
  if (!size_ptr)
    return XDP_ABORTED;
  int size = *size_ptr;
  switch (opcode_host) {
  case MPI_SEND:
    return XDP_PASS;
    break;
  case MPI_BCAST: {
    if (root_host == dst_host) {
      return XDP_PASS;
    } else {
      return XDP_CLONE_PASS(2);
    }
  } break;
  case MPI_BCAST_RING: {
    if (root_host == dst_host) {
      bpf_printk("ho finito in original");
      return XDP_PASS;
    } else {
      // if (src_host == 0 && seq_host == 0) {
      //   start_time = bpf_ktime_get_ns();
      // }
      // __u64 current_time = bpf_ktime_get_ns();
      // __u64 elapsed_ns = current_time - start_time;
      // __u64 elapsed_sec = elapsed_ns / 1000000000;
      // __u64 elapsed_usec = (elapsed_ns % 1000000000) / 1000;
      // bpf_printk("MPI_BCAST_RING: dst=%d, elapsed_time=%lu.%06lu sec",
      // dst_host,
      //            elapsed_sec, elapsed_usec);
      // count_pass++;
      //bpf_printk("ORIGINAL rank: %d, iter: %d", dst_host, seq_host);
      return XDP_CLONE_PASS(1);
    }
  } break;
  case MPI_BCAST_LINEAR: {
    if (root_host == dst_host) {
      // bpf_printk("query size: %d", size);
      return XDP_PASS;
    } else if (root_host == src_host) {
      // bpf_printk("root: %d, src: %d", root_host, src_host);
      count_pass++;
      return XDP_CLONE_PASS(size);
    } else {
      // bpf_printk("size: %d", size);
      return XDP_PASS;
    }
  } break;
  case MPI_REDUCE: {
    return XDP_PASS;
  } break;
  default:
    return XDP_PASS;
    break;
  }
}

SEC("xdp")
int kfunc(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  struct ethhdr *eth;
  struct iphdr *iph;
  struct udphdr *udph;

  // //bpf_printk("mark: %d\n", skb->mark);

  int ret = parse_ip_packet(ctx, &eth, &iph, &udph);
  if (ret >= 0) {
    return ret;
  }

  if (iph->saddr == bpf_htonl(3232261378)) { // src ip 192.168.101.2
                                             // //bpf_printk("handle clone\n");
    if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
      // bpf_printk("handle clone");
      return handle_clone(ctx, eth, iph, udph);
    } else {
      if (start_time == 0) {
        start_time = bpf_ktime_get_ns();
      }
      return handle_original(ctx, eth, iph, udph);
    }
    // } else if (iph->saddr == bpf_htonl(3232261377)) { // src ip
    // 192.168.101.1
    //   //bpf_printk("handle clone\n");
  } else {
    return XDP_DROP;
  }
}

char LICENSE[] SEC("license") = "GPL";
