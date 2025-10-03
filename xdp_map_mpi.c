#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <string.h>

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
  MPI_BCAST,
  MPI_REDUCE,
  MPI_SHATTER,
  MPI_GATHER,
  MPI_SHATTERV,
  MPI_GATHERV
} MPI_Collective;

// Map definition

#define MAX_PACKET_SIZE 1500

// Full packet structure for 1500 bytes
struct full_packet {
  __u32 len;                  // Actual packet length
  __u32 timestamp_hi;         // High 32 bits of timestamp
  __u32 timestamp_lo;         // Low 32 bits of timestamp
  __u32 ingress_ifindex;      // Interface index
  __u8 data[MAX_PACKET_SIZE]; // Full packet data (1500 bytes)
};

// Per-CPU array for temporary storage (avoids stack overflow)
// Each CPU gets its own copy, no contention
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 64); // We only need one slot per CPU
  __type(key, __u32);
  __type(value, struct full_packet);
} temp_packet_storage SEC(".maps");

// Queue map to store full packets (FIFO)
struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(max_entries, 1024); // Adjust based on your needs
  __type(value, struct full_packet);
} full_packet_queue SEC(".maps");

// Alternative: Multiple queues for different packet types/priorities
struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(max_entries, 512);
  __type(value, struct full_packet);
} mpi_packet_queue SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(max_entries, 512);
  __type(value, struct full_packet);
} other_packet_queue SEC(".maps");

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
} mpi_sockets_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, tuple_process);
  __type(value, socket_id);
} mpi_send_map SEC(".maps");

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
  __type(key, __u32);
  __type(value, packet_info);
} info_packet_arr SEC(".maps");

#define NUM_QUEUES 1024 /* number of independent queues */
#define QUEUE_SIZE                                                             \
  128 /* capacity per queue (must be power‑of‑two for mask trick) */
#define QUEUE_MASK (QUEUE_SIZE - 1)

/* Flattened 2D array: [qid][pos] → value */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, NUM_QUEUES *QUEUE_SIZE);
  __type(key, __u32);
  __type(value, packet_info); /* change to whatever element type you need */
} queue_map SEC(".maps");

/* Per‑queue head pointers: qid → dequeue index */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, NUM_QUEUES);
  __type(key, __u32);
  __type(value, __u32);
} head_map SEC(".maps");

/* Per‑queue tail pointers: qid → enqueue index */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, NUM_QUEUES);
  __type(key, __u32);
  __type(value, __u32);
} tail_map SEC(".maps");

/* Enqueue `val` into queue `qid`. Returns 0 on success, -1 if full. */
static __always_inline int queue_enqueue(__u32 qid, packet_info val) {
  __u32 *head = bpf_map_lookup_elem(&head_map, &qid);
  __u32 *tail = bpf_map_lookup_elem(&tail_map, &qid);
  if (!head || !tail)
    return -1;

  __u32 next_tail = (*tail + 1) & QUEUE_MASK;
  /* Full if next_tail would catch up to head */
  if (next_tail == (*head & QUEUE_MASK))
    return -1;

  /* compute flat index and store */
  __u32 flat = qid * QUEUE_SIZE + (*tail & QUEUE_MASK);
  bpf_map_update_elem(&queue_map, &flat, &val, BPF_ANY);
  (*tail)++;
  return 0;
}

/* Dequeue from queue `qid` into `*out`. Returns 0 on success, -1 if empty.
 */
static __always_inline int queue_dequeue(__u32 qid, packet_info *out) {
  __u32 *head = bpf_map_lookup_elem(&head_map, &qid);
  __u32 *tail = bpf_map_lookup_elem(&tail_map, &qid);
  if (!head || !tail)
    return -1;

  if ((*head & QUEUE_MASK) == (*tail & QUEUE_MASK))
    return -1; /* empty */

  __u32 flat = qid * QUEUE_SIZE + (*head & QUEUE_MASK);
  packet_info *val = bpf_map_lookup_elem(&queue_map, &flat);
  if (!val)
    return -1;

  *out = *val;
  (*head)++;
  return 0;
}

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

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Basic packet validation
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    bpf_printk("XDP: Ethernet header validation failed\n");
    return XDP_ABORTED;
  }

  // Only process IP packets
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    bpf_printk("XDP: Non-IP packet, passing through\n");
    return XDP_ABORTED;
  }

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    bpf_printk("XDP: IP header validation failed\n");
    return XDP_ABORTED;
  }

  // Only process UDP packets
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_ABORTED;
  }

  __u32 ip_hdr_len = iph->ihl * 4;
  struct udphdr *udph = (void *)iph + ip_hdr_len;
  if ((void *)(udph + 1) > data_end) {
    bpf_printk("XDP: UDP header validation failed\n");
    return XDP_ABORTED;
  }

  void *l4_hdr = (void *)iph + ip_hdr_len;
  if (l4_hdr + sizeof(struct udphdr) > data_end)
    return XDP_ABORTED;

  // Check socket mapping
  socket_id pkt_id = {.src_ip = iph->saddr,
                      .dst_ip = iph->daddr,
                      .src_port = bpf_ntohs(udph->source),
                      .dst_port = bpf_ntohs(udph->dest),
                      .protocol = iph->protocol};

  tuple_process *value = bpf_map_lookup_elem(&mpi_sockets_map, &pkt_id);
  if (value) {

    bpf_printk("XDP: Processing packet, eth_proto=0x%x",
               bpf_ntohs(eth->h_proto));
    bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
               "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5],
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
               eth->h_dest[4], eth->h_dest[5]);
    __u32 saddr = iph->saddr;
    __u32 daddr = iph->daddr;
    if (saddr == daddr) {
      iph->saddr = 0;
      iph->daddr = 0;
      saddr = iph->saddr;
      daddr = iph->daddr;
      iph->check = ip_checksum_xdp(iph);
    }
    __sum16 check = iph->check;
    __be16 id = iph->id;
    __be16 frag_off = iph->frag_off;
    __sum16 check_udp = udph->check;
    bpf_printk("IP: src=%d.%d.%d.%d dst=%d.%d.%d.%d proto=%d ttl=%d\n",
               ((unsigned char *)&saddr)[0], ((unsigned char *)&saddr)[1],
               ((unsigned char *)&saddr)[2], ((unsigned char *)&saddr)[3],
               ((unsigned char *)&daddr)[0], ((unsigned char *)&daddr)[1],
               ((unsigned char *)&daddr)[2], ((unsigned char *)&daddr)[3],
               iph->protocol, iph->ttl);
    bpf_printk("IP checksum: 0x%04x\n", __builtin_bswap16(check));
    bpf_printk("IP ID: %u, Fragment offset + flags: 0x%x\n", id, frag_off);
    bpf_printk("UDP: sport=%d dport=%d len=%d\n", bpf_ntohs(udph->source),
               bpf_ntohs(udph->dest), bpf_ntohs(udph->len));
    bpf_printk("UDP checksum: 0x%04x\n", __builtin_bswap16(check_udp));
    bpf_printk("XDP: IP packet, protocol=%d", iph->protocol);

    // udph->dest = bpf_htons(5000);

    // bpf_printk("XDP: IP packet, %d->%d", iph->saddr, iph->daddr);

    // bpf_printk("XDP: UDP packet %d->%d", bpf_ntohs(udph->source),
    //            bpf_ntohs(udph->dest));
    bpf_printk("XDP: MPI packet found %d->%d", value->src_procc,
               value->dst_procc);

    void *payload = l4_hdr + sizeof(udph);
    if (payload + sizeof(__u32) <= data_end) {
      __u32 netval = *(__u32 *)payload;
      __u32 val = bpf_ntohl(netval);
      // bpf_printk("val %d", val);
      if ((__s32)val < 0 && (iph->saddr != iph->daddr)) {
        // Modify value: make it positive (for example, flip sign or set abs())
        __u32 new_val = (__u32)(-((__s32)val)); // absolute value

        // bpf_printk("new_val %d", new_val);
        // Write back in network order
        *(__u32 *)payload = bpf_htonl(new_val);
        return XDP_TX; // transmit back after modification
      }
    }
    // Store packet information
    packet_info info = {0};
    info.ingress_ifindex = ctx->ingress_ifindex;
    info.total_len = bpf_ntohs(iph->tot_len);
    info.processed = 1;

    // Safely copy headers with bounds checking
    int copy_len = 14;
    if ((void *)eth + copy_len <= data_end) {
      __builtin_memcpy(info.eth_hdr, eth, copy_len);
    } else {
      bpf_printk("XDP: Ethernet header copy failed\n");
    }

    copy_len = 20;
    if ((void *)iph + copy_len <= data_end) {
      __builtin_memcpy(info.ip_hdr, iph, copy_len);
    } else {
      bpf_printk("XDP: IP header copy failed\n");
    }

    copy_len = 8;
    if ((void *)udph + copy_len <= data_end) {
      __builtin_memcpy(info.udp_hdr, udph, copy_len);
    } else {
      bpf_printk("XDP: UDP header copy failed\n");
    }

    // Try to enqueue
    if (queue_enqueue(value->dst_procc, info) < 0) {
      bpf_printk("XDP: Queue full for process %d\n", value->dst_procc);
      packet_info dropped;
      if (queue_dequeue(value->dst_procc, &dropped) == 0) {
        queue_enqueue(value->dst_procc, info);
      }

    } else {
      bpf_printk("XDP: Packet queued for process %d\n", value->dst_procc);
    }

    return XDP_PASS;
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";