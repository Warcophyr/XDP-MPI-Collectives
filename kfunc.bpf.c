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
#include <linux/if_xdp.h>

#define __XDP_CLONE_PASS 6
#define __XDP_CLONE_TX 7
#define XDP_CLONE_PASS(num_copy)                                               \
  (((int)(num_copy) << 5) | (int)__XDP_CLONE_PASS)
#define XDP_CLONE_TX(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_TX)

typedef enum MPI_Datatype {
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
int __src = 0;

SEC("xdp")
int kfunc(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

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

  if (iph->saddr == bpf_htonl(3232261377)) { // src ip 192.168.101.1
                                             //     bpf_printk("Grecale say i");
    // if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
    //   int iter_copy = 0;
    //   __builtin_memcpy(&iter_copy, data_meta, sizeof(iter_copy));
    //   // bpf_printk("num_copy: %d", num_copy);
    //   if (iter_copy == 0) {
    //     bpf_printk("__src: %d", __src);
    //     __src += 1;
    //     return XDP_CLONE_TX(1);
    //   } else {
    //     bpf_printk("__src: %d", __src);
    //     return XDP_DROP;
    //   }
    // }
    void *payload = (void *)udph + sizeof(*udph);

    const int num_char = 4;
    const int needed = (sizeof(char) * 4) + (sizeof(int) * 3) +
                       sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                       (sizeof(int) * 2) + sizeof(unsigned long);
    if (payload + needed > data_end)
      return XDP_PASS; /* not enough payload */

    char mpi_header[4] = {'a', 'a', 'a', 'a'};
#pragma unroll
    for (int i = 0; i < num_char; i++) {
      __builtin_memcpy(&mpi_header[i], payload + i * sizeof(char),
                       sizeof(char));
    }

    bpf_printk("udp first4: %c %c %c %c\n", mpi_header[0], mpi_header[1],
               mpi_header[2], mpi_header[3]);
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
    __src = src_host;

    int dst;
    void *dst_payload =
        (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 2);
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
    void *len_payload = (char *)payload + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective) +
                        sizeof(MPI_Datatype);
    __builtin_memcpy(&len, len_payload, sizeof(int));
    int len_host = bpf_ntohl(len);

    int tag;
    void *tag_payload = (char *)payload + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective) +
                        sizeof(MPI_Datatype) + sizeof(int);
    __builtin_memcpy(&tag, tag_payload, sizeof(int));
    int tag_host = bpf_ntohl(tag);

    unsigned long seq;
    void *seq_payload = (char *)payload + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective) +
                        sizeof(MPI_Datatype) + (sizeof(int) * 2);
    __builtin_memcpy(&seq, seq_payload, sizeof(unsigned long));
    unsigned long seq_host = bpf_ntohl(seq);

    // bpf_printk("root: %d, src: %d, dst: %d, opcode: %d, datatype: %d,
    //                len : %
    //                d,
    //            "
    //            "tag: %d seq: %lu",
    //            root_host, src_host, dst_host, opcode_host, datatype_host,
    //            len_host, tag_host, seq_host);

    switch (opcode_host) {
    case MPI_SEND:
      return XDP_PASS;
      break;
    case MPI_BCAST: {
      if (root_host == dst_host) {
        return XDP_DROP;
      }
      if (ctx->data + sizeof(__u32) <= ctx->data_end) {
        if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
          int iter_copy = 0;
          __builtin_memcpy(&iter_copy, data_meta, sizeof(iter_copy));
          // bpf_printk("num_copy: %d", num_copy);
          int key_num_process = 0;
          int *size = bpf_map_lookup_elem(&num_process, &key_num_process);
          if (size) {
            if (iter_copy == 0) {
              return XDP_CLONE_PASS(2);
            }
            // bpf_printk("size: %d", *size);
            // int next = (int)(((unsigned)(dst_host + 1)) %
            // ((unsigned)(*size)));
            int next =
                (int)(((unsigned)((2 * src_host) + 1)) % ((unsigned)(*size)));
            if (root_host == next) {
              return XDP_DROP;
            }
            tuple_process inter_dest = {0};
            inter_dest.src_procc = dst_host;
            inter_dest.dst_procc = next;
            socket_id *info_forwad_next =
                bpf_map_lookup_elem(&proc_to_address, &inter_dest);
            if (info_forwad_next) {
              __u8 src_mac[ETH_ALEN];
              __u8 dst_mac[ETH_ALEN];
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
              return XDP_TX;
            }
          }
        } else {
          return XDP_PASS;
        }
      }
    } break;
    case MPI_REDUCE: {
      return XDP_PASS;
    } break;
    default:
      return XDP_DROP;
      break;
    }

    // if (ctx->data + sizeof(__u32) <= ctx->data_end) {

    //   // return XDP_CLONE_TX;
    //   if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
    //     int num_copy = 0;
    //     __builtin_memcpy(&num_copy, data_meta, sizeof(num_copy));
    //     bpf_printk("num_copy: %d", num_copy);
    //     if (num_copy == 0) {

    //       int copy = 2;
    //       int xdp_clone_tx = 6;
    //       int exit_code = 0;
    //       exit_code = (copy << 5) | xdp_clone_tx;
    //       return exit_code;
    //     } else if (num_copy > 0) {
    //       // bpf_printk("XDP_TX_CLONE");
    //       // bpf_printk("copy packet");
    //       // bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
    //       //            "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
    //       //            eth->h_source[0], eth->h_source[1], eth->h_source[2],
    //       //            eth->h_source[3], eth->h_source[4], eth->h_source[5],
    //       //            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    //       //            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    //       __u8 src_mac[ETH_ALEN];
    //       __u8 dst_mac[ETH_ALEN];
    //       __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
    //       __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
    //       __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
    //       __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);
    //       // bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
    //       //            "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
    //       //            eth->h_source[0], eth->h_source[1], eth->h_source[2],
    //       //            eth->h_source[3], eth->h_source[4], eth->h_source[5],
    //       //            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    //       //            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    //       __u32 saddr = iph->saddr;
    //       __u32 daddr = iph->daddr;
    //       __sum16 check = iph->check;
    //       __be16 id = iph->id;
    //       __be16 frag_off = iph->frag_off;
    //       __sum16 check_udp = udph->check;

    //       // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
    //       // bpf_printk("Received Destination IP: 0x%x",
    //       // bpf_ntohl(iph->daddr));
    //       // bpf_printk("IP checksum: 0x%04x\n", __builtin_bswap16(check));
    //       // bpf_printk("IP ID: %u, Fragment offset + flags: 0x%x\n", id,
    //       // frag_off);

    //       __u32 new_daddr = bpf_ntohl(saddr);
    //       __u32 new_saddr = bpf_ntohl(daddr);
    //       iph->saddr = bpf_htonl(new_saddr);
    //       iph->daddr = bpf_htonl(new_daddr);
    //       // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
    //       // bpf_printk("Received Destination IP: 0x%x",
    //       // bpf_ntohl(iph->daddr);

    //       // bpf_printk("UDP: sport=%d dport=%d len=%d\n",
    //       // bpf_ntohs(udph->source),
    //       //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));
    //       udph->dest = bpf_htons(5000);
    //       // udph->dest = 12346;
    //       // udph->check = 0;

    //       // iph->check = ip_checksum_xdp(iph);
    //       // bpf_printk("UDP: sport=%d dport=%d len=%d\n",
    //       // bpf_ntohs(udph->source),
    //       //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));

    //       udph->check = 0;
    //       iph->check = ip_checksum_xdp(iph);
    //       void *l4_hdr = (void *)iph + ip_hdr_len;
    //       if (l4_hdr + sizeof(struct udphdr) > data_end)
    //         return XDP_PASS;
    //       void *payload = l4_hdr + sizeof(udph);
    //       if (payload + sizeof(__u32) <= data_end) {
    //         __u32 netval = *(__u32 *)payload;
    //         __u32 val = bpf_ntohl(netval);
    //         bpf_printk("val %x", val);
    //         // Modify value: make it positive (for example, flip sign or set
    //         // abs())
    //         __u32 new_val = 3; // absolute value
    //         *(__u32 *)payload = bpf_htonl(new_val);

    //         udph->check = 0;
    //         iph->check = ip_checksum_xdp(iph);
    //         return XDP_TX;
    //       }
    //     }
    //     // return XDP_PASS;
    //   }

    //   // bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
    //   //            "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
    //   //            eth->h_source[0], eth->h_source[1], eth->h_source[2],
    //   //            eth->h_source[3], eth->h_source[4], eth->h_source[5],
    //   //            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    //   //            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    //   // __u8 src_mac[ETH_ALEN];
    //   // __u8 dst_mac[ETH_ALEN];
    //   // __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
    //   // __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
    //   // __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
    //   // __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);
    //   // bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
    //   //            "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
    //   //            eth->h_source[0], eth->h_source[1], eth->h_source[2],
    //   //            eth->h_source[3], eth->h_source[4], eth->h_source[5],
    //   //            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    //   //            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    //   // __u32 saddr = iph->saddr;
    //   // __u32 daddr = iph->daddr;
    //   // __sum16 check = iph->check;
    //   // __be16 id = iph->id;
    //   // __be16 frag_off = iph->frag_off;
    //   // __sum16 check_udp = udph->check;

    //   // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
    //   // bpf_printk("Received Destination IP: 0x%x", bpf_ntohl(iph->daddr));
    //   // // bpf_printk("IP checksum: 0x%04x\n", __builtin_bswap16(check));
    //   // // bpf_printk("IP ID: %u, Fragment offset + flags: 0x%x\n", id,
    //   // // frag_off);

    //   // __u32 new_daddr = bpf_ntohl(saddr);
    //   // __u32 new_saddr = bpf_ntohl(daddr);
    //   // iph->saddr = bpf_htonl(new_saddr);
    //   // iph->daddr = bpf_htonl(new_daddr);
    //   // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
    //   // bpf_printk("Received Destination IP: 0x%x", bpf_ntohl(iph->daddr));

    //   // bpf_printk("UDP: sport=%d dport=%d len=%d\n",
    //   // bpf_ntohs(udph->source),
    //   //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));
    //   // // udph->dest = bpf_htons(12346);
    //   // // udph->dest = 12346;
    //   // // udph->check = 0;

    //   // iph->check = ip_checksum_xdp(iph);
    //   // bpf_printk("UDP: sport=%d dport=%d len=%d\n",
    //   // bpf_ntohs(udph->source),
    //   //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));

    //   // void *l4_hdr = (void *)iph + ip_hdr_len;
    //   // if (l4_hdr + sizeof(struct udphdr) > data_end)
    //   //   return XDP_PASS;
    //   // void *payload = l4_hdr + sizeof(udph);
    //   // if (payload + sizeof(__u32) <= data_end) {
    //   //   __u32 netval = *(__u32 *)payload;
    //   //   __u32 val = bpf_ntohl(netval);
    //   //   bpf_printk("val %x", val);
    //   //   // Modify value: make it positive (for example, flip sign or set
    //   //   // abs())
    //   //   __u32 new_val = 2; // absolute value
    //   //   *(__u32 *)payload = bpf_htonl(new_val);

    //   //   bpf_printk("new_val %x", new_val);
    //   //   // Write back in network order
    //   //   udph->check = 0;
    //   //   iph->check = ip_checksum_xdp(iph);
    //   // }
    //   // return XDP_TX;
    //   // return XDP_CLONE;
    //   return XDP_PASS;
    // }
    // short x = 2;
    // short y = 3;
    // int z = 0;
    // z = ((int)x << 16);
    // return z;
    return XDP_PASS;
  }
  if (iph->saddr == bpf_htonl(3232261378)) { // src ip 192.168.101.1
                                             //     bpf_printk("Grecale say i");
    void *payload = (void *)udph + sizeof(*udph);

    const int num_char = 4;
    const int needed = (sizeof(char) * 4) + (sizeof(int) * 3) +
                       sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                       (sizeof(int) * 2) + sizeof(unsigned long);
    if (payload + needed > data_end)
      return XDP_PASS; /* not enough payload */

    char mpi_header[4] = {'a', 'a', 'a', 'a'};
#pragma unroll
    for (int i = 0; i < num_char; i++) {
      __builtin_memcpy(&mpi_header[i], payload + i * sizeof(char),
                       sizeof(char));
    }

    bpf_printk("udp first4: %c %c %c %c\n", mpi_header[0], mpi_header[1],
               mpi_header[2], mpi_header[3]);
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

    int dst;
    void *dst_payload =
        (char *)payload + (sizeof(char) * 4) + (sizeof(int) * 2);
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
    void *len_payload = (char *)payload + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective) +
                        sizeof(MPI_Datatype);
    __builtin_memcpy(&len, len_payload, sizeof(int));
    int len_host = bpf_ntohl(len);

    int tag;
    void *tag_payload = (char *)payload + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective) +
                        sizeof(MPI_Datatype) + sizeof(int);
    __builtin_memcpy(&tag, tag_payload, sizeof(int));
    int tag_host = bpf_ntohl(tag);

    unsigned long seq;
    void *seq_payload = (char *)payload + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective) +
                        sizeof(MPI_Datatype) + (sizeof(int) * 2);
    __builtin_memcpy(&seq, seq_payload, sizeof(unsigned long));
    unsigned long seq_host = bpf_ntohl(seq);

    // bpf_printk("root: %d, src: %d, dst: %d, opcode: %d, datatype: %d,
    //                len : %
    //                d,
    //            "
    //            "tag: %d seq: %lu",
    //            root_host, src_host, dst_host, opcode_host, datatype_host,
    //            len_host, tag_host, seq_host);

    switch (opcode_host) {
    case MPI_SEND:
      return XDP_PASS;
      break;
    case MPI_BCAST: {
      if (root_host == dst_host) {
        return XDP_DROP;
      }
      if (ctx->data + sizeof(__u32) <= ctx->data_end) {
        if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
          int iter_copy = 0;
          __builtin_memcpy(&iter_copy, data_meta, sizeof(iter_copy));
          // bpf_printk("num_copy: %d", num_copy);
          int key_num_process = 0;
          int *size = bpf_map_lookup_elem(&num_process, &key_num_process);
          if (size) {
            if (iter_copy == 0) {
              return XDP_CLONE_PASS(2);
            }
            // bpf_printk("size: %d", *size);
            // int next = (int)(((unsigned)(dst_host + 1)) %
            // ((unsigned)(*size)));
            int next =
                (int)(((unsigned)((2 * __src) + 2)) % ((unsigned)(*size)));
            if (root_host == next) {
              return XDP_DROP;
            }
            tuple_process inter_dest = {0};
            inter_dest.src_procc = __src;
            inter_dest.dst_procc = next;
            socket_id *info_forwad_next =
                bpf_map_lookup_elem(&proc_to_address, &inter_dest);
            if (info_forwad_next) {
              __u8 src_mac[ETH_ALEN];
              __u8 dst_mac[ETH_ALEN];
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
              return XDP_TX;
            }
          }
        } else {
          return XDP_PASS;
        }
      }
    } break;
    case MPI_REDUCE: {
      return XDP_PASS;
    } break;
    default:
      return XDP_DROP;
      break;
    }

    return XDP_PASS;
  }

  // if (iph->saddr == bpf_htonl(3232261378)) {

  //   // __u8 src_mac[ETH_ALEN];
  //   // __u8 dst_mac[ETH_ALEN];
  //   // __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
  //   // __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
  //   // __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
  //   // __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);
  //   // // bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
  //   // //            "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
  //   // //            eth->h_source[0], eth->h_source[1], eth->h_source[2],
  //   // //            eth->h_source[3], eth->h_source[4], eth->h_source[5],
  //   // //            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
  //   // //            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

  //   // __u32 saddr = iph->saddr;
  //   // __u32 daddr = iph->daddr;
  //   // __sum16 check = iph->check;
  //   // __be16 id = iph->id;
  //   // __be16 frag_off = iph->frag_off;
  //   // __sum16 check_udp = udph->check;

  //   // // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
  //   // // bpf_printk("Received Destination IP: 0x%x",
  //   // // bpf_ntohl(iph->daddr));
  //   // // bpf_printk("IP checksum: 0x%04x\n", __builtin_bswap16(check));
  //   // // bpf_printk("IP ID: %u, Fragment offset + flags: 0x%x\n", id,
  //   // // frag_off);

  //   // __u32 new_daddr = bpf_ntohl(saddr);
  //   // __u32 new_saddr = bpf_ntohl(daddr);
  //   // iph->saddr = bpf_htonl(new_saddr);
  //   // iph->daddr = bpf_htonl(new_daddr);
  //   // // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
  //   // // bpf_printk("Received Destination IP: 0x%x",
  //   // // bpf_ntohl(iph->daddr);

  //   // // bpf_printk("UDP: sport=%d dport=%d len=%d\n",
  //   // // bpf_ntohs(udph->source),
  //   // //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));
  //   // udph->dest = bpf_htons(5000);
  //   // // udph->dest = 12346;
  //   // // udph->check = 0;

  //   // // iph->check = ip_checksum_xdp(iph);
  //   // // bpf_printk("UDP: sport=%d dport=%d len=%d\n",
  //   // // bpf_ntohs(udph->source),
  //   // //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));

  //   // udph->check = 0;
  //   // iph->check = ip_checksum_xdp(iph);

  //   int claim = ctx->data_meta + sizeof(__u32) <= ctx->data;
  //   bpf_printk("data_meta: %d data: %d", ctx->data_meta, ctx->data);
  //   if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
  //     int num_copy = 0;
  //     bpf_printk("ip: %lu", bpf_ntohl(iph->saddr));
  //     __builtin_memcpy(&num_copy, data_meta, sizeof(num_copy));
  //     bpf_printk("num_copy: %d", num_copy);
  //     if (num_copy == 0) {

  //       int copy = 1;
  //       int xdp_clone_tx = 6;
  //       int exit_code = 0;
  //       exit_code = (copy << 5) | xdp_clone_tx;
  //       return exit_code;
  //     } else if (num_copy > 0) {
  //       void *l4_hdr = (void *)iph + ip_hdr_len;
  //       // if (l4_hdr + sizeof(struct udphdr) > data_end)
  //       //   return XDP_PASS;
  //       void *payload = l4_hdr + sizeof(udph);
  //       if (payload + sizeof(__u32) <= data_end) {
  //         __u32 netval = *(__u32 *)payload;
  //         __u32 val = bpf_ntohl(netval);
  //         bpf_printk("val %x", val);
  //         // Modify value: make it positive (for example, flip sign or set
  //         // abs())
  //         __u32 new_val = 2; // absolute value
  //         *(__u32 *)payload = bpf_htonl(new_val);

  //         udph->check = 0;
  //         iph->check = ip_checksum_xdp(iph);
  //         return XDP_TX;
  //       }
  //     }
  //     return XDP_PASS;
  //   }
  // }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";