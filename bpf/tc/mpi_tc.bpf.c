// do not change the order of the include
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>


// #ifdef DEBUG
// #define //bpf_printk(fmt, ...)                                                   \
//   ({                                                                           \
//     char ____fmt[] = fmt;                                                        \
//     bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
//   })
// #else
// #define //bpf_printk(fmt, ...)                                                   \
//   do {                                                                        \
//   } while (0)
// #endif

#define MAGICK_MARK 0xbabe

#define __XDP_CLONE_PASS 5
#define __XDP_CLONE_TX 6
#define XDP_CLONE_PASS(num_copy)                                               \
  (((int)(num_copy) << 5) | (int)__XDP_CLONE_PASS)
#define XDP_CLONE_TX(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_TX)

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
// int __src_host = 0;
__u32 count = 0;

static __always_inline int parse_ip_packet(struct __sk_buff *skb,
                                           struct iphdr **out_iph) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    //bpf_printk("TC: Ethernet header validation failed\n");
    return TC_ACT_OK;
  }

  // Only process IP packets. Pass others through safely.
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    // //bpf_printk("TC: Non-IP packet, passing through\n");
    return TC_ACT_OK; // FIXED: TC_ACT_OK allows the packet to continue
  }

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    //bpf_printk("TC: IP header validation failed\n");
    return TC_ACT_OK;
  }

  // eBPF Verifier requirement: ensure the IP header length is at least
  // 5 words (20 bytes) to prevent invalid offsets.
  if (iph->ihl < 5) {
    //bpf_printk("TC: Invalid IP header length\n");
    return TC_ACT_OK;
  }

  // Only process UDP packets. Pass others through safely.
  if (iph->protocol != IPPROTO_UDP) {
    // //bpf_printk("TC: Non-UDP packet, passing through\n");
    return TC_ACT_OK;
  }

  // Successfully parsed. Assign the IP header pointer back to the caller.
  if (out_iph) {
    *out_iph = iph;
  }

  return -1;
}

static __always_inline int handle_clone(struct __sk_buff *skb,
                                        struct iphdr *iph) {

  if (!iph) {
    //bpf_printk("TC: IP header is NULL in handle_clone\n");
    return TC_ACT_OK;
  }
  struct udphdr *udph = (void *)iph + iph->ihl * 4;
  if ((void *)udph + 1 > (void *)(long)skb->data_end) {
    //bpf_printk("TC: UDP header validation failed\n");
    return TC_ACT_OK;
  }

  void *payload = (void *)udph + sizeof(*udph);

  const int num_char = 4;
  const int needed = (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2) + sizeof(unsigned long) +
                     sizeof(unsigned long);

  if ((void *)payload + needed > (void *)(long)skb->data_end) {
    //bpf_printk("TC: Not enough payload\n");
    return TC_ACT_OK; /* not enough payload */
  }

  char mpi_header[4] = {'a', 'a', 'a', 'a'};
#pragma unroll
  for (int i = 0; i < num_char; i++) {
    __builtin_memcpy(&mpi_header[i], payload + i * sizeof(char), sizeof(char));
  }

  // //bpf_printk("udp first4: %c %c %c %c\n", mpi_header[0], mpi_header[1],
  //            mpi_header[2], mpi_header[3]);
  if (mpi_header[0] != 'M' && mpi_header[1] != 'P' && mpi_header[2] != 'I' &&
      mpi_header[3] != '\0') {
    return TC_ACT_OK;
  }

  int root;
  void *root_payload = (char *)payload + (sizeof(char) * 4);
  __builtin_memcpy(&root, root_payload, sizeof(int));
  int root_host = bpf_ntohl(root);

  int src;
  void *src_payload = (char *)payload + (sizeof(char) * 4) + sizeof(int);
  __builtin_memcpy(&src, src_payload, sizeof(int));
  int src_host = bpf_ntohl(src);

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

  // //bpf_printk(
  //     "CASE 2 root: %d, src: %d, dst: %d, opcode: %d, datatype: %d, len : "
  //     "%d, tag: %d seq: %lu clock: %lu",
  //     root_host, src_host, dst_host, opcode_host, datatype_host, len_host,
  //     tag_host, seq_host, clock_host);
  // count = dst_host == 3 ? count + 1 : count;
  // if (dst_host == 3) {

  //   //bpf_printk("root: %d, src: %d, dst: %d, opcode: %d, datatype: %d, len "
  //              ":%d,tag : %d seq : %lu clock : %lu count: %d",
  //              root_host, src_host, dst_host, opcode_host, datatype_host,
  //              len_host, tag_host, seq_host, clock_host, count);
  // }

  switch (opcode_host) {
  case MPI_SEND:
    return TC_ACT_OK;
    break;
  // case MPI_BCAST: {
  //   if (root_host == dst_host) {
  //     return TC_ACT_OK;
  //   }
  //   if (skb->data + sizeof(__u32) <= skb->data_end) {
  //     if (skb->data_meta + sizeof(__u32) <= skb->data) {
  //       int iter_copy = 0;
  //       __builtin_memcpy(&iter_copy, data_meta, sizeof(iter_copy));
  //       // //bpf_printk("CASE 2 iter: %d root: %d, src: %d, dst: %d, opcode:
  //       %d,
  //       // "
  //       //            "datatype: %d, len : "
  //       //            "%d, tag: %d seq: %lu clock: %lu",
  //       //            iter_copy, root_host, src_host, dst_host,
  //       opcode_host,
  //       //            datatype_host, len_host, tag_host, seq_host,
  //       //            clock_host);
  //       // //bpf_printk("old_src_ip %lu", bpf_ntohl(iph->saddr));
  //       int key_num_process = 0;
  //       int *size_ptr = bpf_map_lookup_elem(&num_process,
  //       &key_num_process); if (size_ptr) {
  //         int size = *size_ptr;
  //         int ret = bpf_clone_redirect(skb, skb->ingress_ifindex,
  //         BPF_F_INGRESS); if (ret < 0) {
  //           //bpf_printk("Clone redirect failed: %d", ret);
  //           return TC_ACT_OK;
  //         }

  //         // //bpf_printk("size: %d", *size);
  //         // int next = (int)(((unsigned)(dst_host + 1)) %
  //         // ((unsigned)(*size)));
  //         // if (src_host > (int)((unsigned int)size / 2)) {
  //         //   return TC_ACT_OK;
  //         // }
  //         int next = (2 * src_host) + 2;
  //         // (int)(((unsigned)((2 * src_host) + 2)) % ((unsigned)(size)));
  //         if (next >= size) {
  //           // //bpf_printk("hi 2");
  //           return TC_ACT_OK;
  //         }
  //         tuple_process inter_dest = {0};
  //         inter_dest.src_procc = src_host;
  //         inter_dest.dst_procc = next;
  //         socket_id *info_forwad_next =
  //             bpf_map_lookup_elem(&proc_to_address, &inter_dest);
  //         if (info_forwad_next) {
  //           // __u8 src_mac[ETH_ALEN];
  //           // __u8 dst_mac[ETH_ALEN];
  //           // __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
  //           // __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
  //           // __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
  //           // __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);

  //           int dst_net = bpf_htonl(src_host);
  //           int next_net = bpf_htonl(next);
  //           __builtin_memcpy(src_payload, &dst_net, sizeof(int));
  //           __builtin_memcpy(dst_payload, &next_net, sizeof(int));

  //           udph->source = bpf_htons(info_forwad_next->src_port);
  //           udph->dest = bpf_htons(info_forwad_next->dst_port);
  //           udph->check = 0;

  //           iph->saddr = info_forwad_next->src_ip;
  //           iph->daddr = info_forwad_next->dst_ip;
  //           iph->check = ip_checksum_xdp(iph);
  //           // //bpf_printk("new_src: %d next: %d src_port: %d dst_port: %d "
  //           //            "src_ip: %ld dst_ip: %ld",
  //           //            src_host, next, info_forwad_next->src_port,
  //           //            info_forwad_next->dst_port,
  //           //            info_forwad_next->src_ip,
  //           info_forwad_next->dst_ip);
  //           // //bpf_printk("src_ip: %lu", bpf_ntohl(iph->saddr));
  //           // //bpf_printk("dst_ip: %lu", bpf_ntohl(iph->daddr));
  //           // __src = 0;
  //           return bpf_redirect(skb->ingress_ifindex, 0);
  //         }
  //       }
  //     } else {
  //       return TC_ACT_OK;
  //     }
  //   }
  // } break;
  case MPI_BCAST_RING: {
    if (root_host == dst_host) {
      return TC_ACT_OK;
    }

    //   __builtin_memcpy(&iter_copy, data_meta, sizeof(iter_copy));
    // //bpf_printk("num_copy: %d", num_copy);
    int key_num_process = 0;
    int *size_ptr = bpf_map_lookup_elem(&num_process, &key_num_process);
    if (!size_ptr) {
      return TC_ACT_OK;
    }

    int next = (int)(((unsigned)((dst_host) + 1)) % ((unsigned)(*size_ptr)));
    if (root_host == next) {
      return TC_ACT_OK;
    }

    tuple_process inter_dest = {0};
    inter_dest.src_procc = dst_host;
    inter_dest.dst_procc = next;
    socket_id *info_forwad_next =
        bpf_map_lookup_elem(&proc_to_address, &inter_dest);

    if (info_forwad_next) {
      __u8 src_mac[ETH_ALEN];
      __u8 dst_mac[ETH_ALEN];
      struct ethhdr *eth = (void *)(long)skb->data;
      if ((void *)(eth + 1) > (void *)(long)skb->data_end) {
        return TC_ACT_OK;
      }
      __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
      __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
      __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
      __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);

      int dst_net = bpf_htonl(dst_host);
      int next_net = bpf_htonl(next);

      __builtin_memcpy(src_payload, &dst_net, sizeof(int));
      __builtin_memcpy(dst_payload, &next_net, sizeof(int));

      udph->source = bpf_htons(info_forwad_next->src_port);
      udph->dest = bpf_htons(info_forwad_next->dst_port);
      udph->check = 0;

      iph->saddr = info_forwad_next->src_ip;
      iph->daddr = info_forwad_next->dst_ip;
      iph->check = ip_checksum_xdp(iph);

      // //bpf_printk("src_ip: %lu", bpf_ntohl(iph->saddr));
      // //bpf_printk("dst_ip: %lu", bpf_ntohl(iph->daddr));
      return bpf_redirect(skb->ingress_ifindex, 0);
    }
  } break;
  case MPI_REDUCE: {
    return TC_ACT_OK;
  } break;
  default:
    return TC_ACT_OK;
    break;
  }

  return TC_ACT_OK;
}

static __always_inline int handle_original(struct __sk_buff *skb,
                                           struct iphdr *iph) {

  if (!iph) {
    //bpf_printk("TC: IP header is NULL in handle_clone\n");
    return TC_ACT_OK;
  }
  struct udphdr *udph = (void *)iph + iph->ihl * 4;
  if (udph + 1 > (void *)(long)skb->data_end) {
    //bpf_printk("TC: UDP header validation failed\n");
    return TC_ACT_OK;
  }

  void *payload = (void *)udph + sizeof(*udph);

  const int num_char = 4;
  const int needed = (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2) + sizeof(unsigned long) +
                     sizeof(unsigned long);
  if (payload + needed > skb->data_end)
    return TC_ACT_OK; /* not enough payload */

  char mpi_header[4] = {'a', 'a', 'a', 'a'};
#pragma unroll
  for (int i = 0; i < num_char; i++) {
    __builtin_memcpy(&mpi_header[i], payload + i * sizeof(char), sizeof(char));
  }

  // //bpf_printk("udp first4: %c %c %c %c\n", mpi_header[0], mpi_header[1],
  //            mpi_header[2], mpi_header[3]);
  if (mpi_header[0] != 'M' && mpi_header[1] != 'P' && mpi_header[2] != 'I' &&
      mpi_header[3] != '\0') {
    return TC_ACT_OK;
  }

  int root;
  void *root_payload = (char *)payload + (sizeof(char) * 4);
  __builtin_memcpy(&root, root_payload, sizeof(int));
  int root_host = bpf_ntohl(root);

  int src;
  // print 64 byte payload
  // for (int i = 0; i < 64; i++) {
  //   __u8 c;
  //   if ((char *)payload + i >= (char *)skb->data_end) {
  //     break;
  //   }
  //   __builtin_memcpy(&c, payload + i, sizeof(__u8));
  //   //bpf_printk("payload byte %d: %02x\n", i, c);
  // }

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

  //bpf_printk(
      // "CASE 1 root: %d, src: %d, dst: %d, opcode: %d, datatype: %d, len : "
      // "%d, tag: %d seq: %lu clock: %lu",
      // root_host, src_host, dst_host, opcode_host, datatype_host, len_host,
      // tag_host, seq_host, clock_host);
  // count = dst_host == 3 ? count + 1 : count;
  // if (dst_host == 3) {

  //   //bpf_printk("root: %d, src: %d, dst: %d, opcode: %d, datatype: %d, len:
  //   "
  //              "%d,tag : %d seq : %lu clock : %lu count: %d",
  //              root_host, src_host, dst_host, opcode_host, datatype_host,
  //              len_host, tag_host, seq_host, clock_host, count);
  // }

  switch (opcode_host) {
  case MPI_SEND:
    return TC_ACT_OK;

    // case MPI_BCAST: {
    //   if (root_host == dst_host) {
    //     return TC_ACT_OK;
    //   }
    //   if (skb->data + sizeof(__u32) <= skb->data_end) {
    //     int key_num_process = 0;
    //     int *size_ptr = bpf_map_lookup_elem(&num_process,
    //     &key_num_process); if (size_ptr) {
    //       int size = *size_ptr;
    //       // //bpf_printk(
    //       //     "CASE 0 iter: %d root: %d, src: %d, dst: %d, opcode: %d, "
    //       //     "datatype: %d, len : "
    //       //     "%d, tag: %d seq: %lu clock: %lu",
    //       //     iter_copy, root_host, src_host, dst_host, opcode_host,
    //       //     datatype_host, len_host, tag_host, seq_host, clock_host);
    //       int ret =
    //           bpf_clone_redirect(skb, skb->ingress_ifindex, BPF_F_INGRESS);
    //       if (ret < 0) {
    //         //bpf_printk("Clone redirect failed: %d", ret);
    //         return TC_ACT_OK;
    //       }

    //       // //bpf_printk(
    //       //     "CASE 1 iter: %d root: %d, src: %d, dst: %d, opcode: %d, "
    //       //     "datatype: %d, len : "
    //       //     "%d, tag: %d seq: %lu clock: %lu",
    //       //     iter_copy, root_host, src_host, dst_host, opcode_host,
    //       //     datatype_host, len_host, tag_host, seq_host, clock_host);
    //       // //bpf_printk("size: %d", *size);
    //       // int next = (int)(((unsigned)(dst_host + 1)) %
    //       // ((unsigned)(*size)));
    //       // if (src_host > (int)((unsigned int)size / 2)) {
    //       //   return TC_ACT_OK;
    //       // }
    //       int next = (2 * dst_host) + 1;
    //       // (int)(((unsigned)((2 * dst_host) + 1)) % ((unsigned)(size)));
    //       if (next >= size) {
    //         // //bpf_printk("hi 1");
    //         return TC_ACT_OK;
    //       }
    //       tuple_process inter_dest = {0};
    //       inter_dest.src_procc = dst_host;
    //       inter_dest.dst_procc = next;
    //       socket_id *info_forwad_next =
    //           bpf_map_lookup_elem(&proc_to_address, &inter_dest);
    //       if (info_forwad_next) {
    //         __u8 src_mac[ETH_ALEN];
    //         __u8 dst_mac[ETH_ALEN];
    //         __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
    //         __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
    //         __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
    //         __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);

    //         int dst_net = bpf_htonl(dst_host);
    //         int next_net = bpf_htonl(next);
    //         // //bpf_printk("new_src: %d next: %d", dst_host, next);
    //         __builtin_memcpy(src_payload, &dst_net, sizeof(int));
    //         __builtin_memcpy(dst_payload, &next_net, sizeof(int));

    //         udph->source = bpf_htons(info_forwad_next->src_port);
    //         udph->dest = bpf_htons(info_forwad_next->dst_port);
    //         udph->check = 0;

    //         iph->saddr = info_forwad_next->src_ip;
    //         iph->daddr = info_forwad_next->dst_ip;
    //         iph->check = ip_checksum_xdp(iph);
    //         // //bpf_printk("new_src: %d next: %d src_port: %d dst_port: %d "
    //         //            "src_ip: %ld dst_ip: %ld",
    //         //            dst_host, next, info_forwad_next->src_port,
    //         //            info_forwad_next->dst_port,
    //         //            info_forwad_next->src_ip,
    //         info_forwad_next->dst_ip);
    //         // //bpf_printk("src_ip: %lu", bpf_ntohl(iph->saddr));
    //         // //bpf_printk("dst_ip: %lu", bpf_ntohl(iph->daddr));
    //         return bpf_redirect(skb->ingress_ifindex, 0);
    //       }
    //     }
    //   } else {
    //     return TC_ACT_OK;
    //   }
    //   break;
    // }

  case MPI_BCAST_RING: {
    if (root_host == dst_host) {
      return TC_ACT_OK;
    }
    int key_num_process = 0;
    int *size_ptr = bpf_map_lookup_elem(&num_process, &key_num_process);
    if (!size_ptr)
      return TC_ACT_OK;

    skb->mark = MAGICK_MARK;

    // clone original packet and send to the application
    int ret = bpf_clone_redirect(skb, skb->ingress_ifindex, BPF_F_INGRESS);
    if (ret < 0) {
      //bpf_printk("Clone redirect failed: %d", ret);
      return TC_ACT_OK;
    }

    skb->mark = 0;

    // parse again the packet bc the clone
    ret = parse_ip_packet(skb, &iph);
    if (ret >= 0) {
      //bpf_printk("Failed to parse cloned packet: %d", ret);
      return ret;
    }

    return handle_clone(skb, iph);
  }

  case MPI_REDUCE:
    return TC_ACT_OK;

  default:
    return TC_ACT_OK;
  }

  return TC_ACT_OK;
}

SEC("tc/ingress")
int kfunc(struct __sk_buff *skb) {
  if (skb->mark == MAGICK_MARK) {
    skb->mark = 0;
    //bpf_printk("Passing original cloned packet\n");
    struct iphdr *iph;

    int ret = parse_ip_packet(skb, &iph);
    if (ret >= 0) {
      //bpf_printk("Failed to parse cloned packet: %d", ret);
      return ret;
    }

    // //bpf_printk("IP: src: %pI4 dst: %pI4, \n", &iph->saddr, &iph->daddr);

    return TC_ACT_OK; // Allow the cloned packet to continue to the application
  }
  struct iphdr *iph;

  // //bpf_printk("mark: %d\n", skb->mark);

  int ret = parse_ip_packet(skb, &iph);
  if (ret >= 0) {
    return ret;
  }

  if (iph->saddr == bpf_htonl(3232261378)) { // src ip 192.168.101.2
    return handle_original(skb, iph);
  }

  // //bpf_printk("TC: Packet from other source, passing through\n");

  return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";