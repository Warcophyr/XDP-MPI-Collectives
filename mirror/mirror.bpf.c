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

#define __XDP_CLONE_PASS 5
#define __XDP_CLONE_TX 6
#define XDP_CLONE_PASS(num_copy)                                               \
  (((int)(num_copy) << 5) | (int)__XDP_CLONE_PASS)
#define XDP_CLONE_TX(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_TX)

#ifdef DEBUG
#define bpf_printk(fmt, ...)                                                   \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })
#else
#define bpf_printk(fmt, ...)                                                   \
  do {                                                                         \
  } while (0)
#endif

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

SEC("xdp")
int mirror(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  // Basic packet validation
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    bpf_printk("XDP: Ethernet header validation failed\n");
    return XDP_PASS;
  }

  // Only process IP packets
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    bpf_printk("XDP: Non-IP packet, passing through\n");
    return XDP_PASS;
  }

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    bpf_printk("XDP: IP header validation failed\n");
    return XDP_PASS;
  }

  // Only process UDP packets
  if (iph->protocol != IPPROTO_UDP) {
    bpf_printk("XDP: UDP proto noonononono");
    return XDP_TX;
  }

  __u32 ip_hdr_len = iph->ihl * 4;

  if (iph->saddr == bpf_htonl(3232261377)) { // src ip 192.168.101.1
                                             //
    // if (iph->saddr == bpf_htonl(3232261386)) { // src ip 192.168.101.10
    struct udphdr *udph = (void *)iph + ip_hdr_len;

    if ((void *)(udph + 1) > data_end) {
      bpf_printk("XDP: UDP header validation failed\n");
      return XDP_PASS;
    }

    void *payload = (void *)udph + sizeof(*udph);

    const int num_char = 4;
    const int needed = (sizeof(char) * 4) + (sizeof(int) * 3) +
                       sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                       (sizeof(int) * 2) + sizeof(unsigned long) +
                       sizeof(unsigned long);

    if ((void *)payload + needed > (void *)(long)ctx->data_end) {
      bpf_printk("XDP: Not enough payload\n");
      return XDP_PASS; /* not enough payload */
    }
    char mpi_header[4] = {'a', 'a', 'a', 'a'};
    for (int i = 0; i < num_char; i++) {
      __builtin_memcpy(&mpi_header[i], payload + i * sizeof(char),
                       sizeof(char));
    }

    // bpf_printk("udp first4: %c %c %c %c\n", mpi_header[0], mpi_header[1],
    //            mpi_header[2], mpi_header[3]);
    if (mpi_header[0] != 'M' && mpi_header[1] != 'P' && mpi_header[2] != 'I' &&
        mpi_header[3] != '\0') {
      return XDP_PASS;
    }

    int src;
    void *src_payload = (char *)payload + (sizeof(char) * 4) + sizeof(int);
    __builtin_memcpy(&src, src_payload, sizeof(int));
    int src_host = bpf_ntohl(src);

    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];
    struct ethhdr *eth = (void *)(long)ctx->data;
    if ((void *)(eth + 1) > (void *)(long)ctx->data_end) {
      return XDP_DROP;
    }
    __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);

    bpf_printk("src %pI4, dts: %pI4", &iph->saddr, &iph->daddr);
    __u32 src_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = src_ip;
    iph->check = ip_checksum_xdp(iph);
    count++;
    return XDP_TX;
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
