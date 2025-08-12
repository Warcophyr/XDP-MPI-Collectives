#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <string.h>

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
  __uint(max_entries, 1); // We only need one slot per CPU
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

static __always_inline int copy_packet_data(__u8 *dst, void *src, void *src_end,
                                            __u32 max_len) {
  __u8 *src_ptr = (__u8 *)src;
  __u32 packet_len = src_end - src;

  if (packet_len > max_len)
    packet_len = max_len;

  // Manual byte-by-byte copying (XDP compatible)
  // #pragma unroll
  for (int i = 0; i < 1500; i++) {
    // Critical bounds checking for each byte
    if (i >= packet_len)
      break;
    if ((void *)(src_ptr + i + 1) > src_end)
      break;
    if (i >= MAX_PACKET_SIZE)
      break;

    dst[i] = src_ptr[i];
  }

  return packet_len;
}

static __always_inline int store_full_packet(struct xdp_md *ctx,
                                             int is_mpi_packet) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Get per-CPU temporary storage (no stack overflow)
  __u32 key = 0;
  struct full_packet *pkt = bpf_map_lookup_elem(&temp_packet_storage, &key);
  if (!pkt) {
    bpf_printk("Failed to get temp storage\n");
    return -1;
  }

  // Calculate packet size
  __u32 packet_size = data_end - data;
  if (packet_size > MAX_PACKET_SIZE)
    packet_size = MAX_PACKET_SIZE;

  // Fill metadata
  pkt->len = packet_size;
  pkt->ingress_ifindex = ctx->ingress_ifindex;

  // Split 64-bit timestamp into two 32-bit values to avoid alignment issues
  __u64 timestamp = bpf_ktime_get_ns();
  pkt->timestamp_hi = (__u32)(timestamp >> 32);
  pkt->timestamp_lo = (__u32)(timestamp & 0xFFFFFFFF);

  // Initialize packet data area (XDP compatible way)
  // #pragma unroll
  // for (int i = 0; i < 1500; i++) {
  //   pkt->data[i] = 0;
  // }

  // Copy full packet data
  int copied = copy_packet_data(pkt->data, data, data_end, MAX_PACKET_SIZE);
  if (copied < 0) {
    bpf_printk("Failed to copy packet data\n");
    return -1;
  }

  pkt->len = copied; // Update with actual copied length

  // Push to appropriate queue
  long err;
  if (is_mpi_packet) {
    err = bpf_map_push_elem(&mpi_packet_queue, pkt, BPF_ANY);
    if (err != 0) {
      bpf_printk("MPI queue full, error: %ld\n", err);
      return -1;
    }
    bpf_printk("Stored MPI packet (%u bytes) in queue\n", pkt->len);
  } else {
    err = bpf_map_push_elem(&other_packet_queue, pkt, BPF_ANY);
    if (err != 0) {
      bpf_printk("Other queue full, error: %ld\n", err);
      return -1;
    }
    bpf_printk("Stored packet (%u bytes) in other queue\n", pkt->len);
  }

  return 0;
}

static __always_inline int compare_with_stored_packet(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Get current packet info
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return -1;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return -1;

  if (iph->protocol != IPPROTO_UDP)
    return -1;

  // Try to retrieve a stored packet for comparison
  __u32 key = 0;
  struct full_packet *stored_pkt =
      bpf_map_lookup_elem(&temp_packet_storage, &key);
  if (!stored_pkt)
    return -1;

  if (bpf_map_pop_elem(&mpi_packet_queue, stored_pkt) != 0) {
    // No stored packets to compare
    return -1;
  }

  bpf_printk("Comparing current packet with stored packet");

  // Compare current packet with stored packet
  if (stored_pkt->len >= 34) {
    struct iphdr *stored_iph = (struct iphdr *)(stored_pkt->data + 14);

    if (iph->saddr == stored_iph->daddr && iph->daddr == stored_iph->saddr) {
      bpf_printk("Found reverse direction packet!");
      // This is a response to the stored packet

      // You could:
      // 1. Process the pair together
      // 2. Calculate latency
      // 3. Match MPI request/response
      return 1; // Found matching pair
    }
  }

  // Put the packet back if no match (optional - or process it differently)
  bpf_map_push_elem(&mpi_packet_queue, stored_pkt, BPF_ANY);
  return 0;
}

static __always_inline int process_stored_packets() {
  __u32 key = 0;
  struct full_packet *temp_pkt =
      bpf_map_lookup_elem(&temp_packet_storage, &key);
  if (!temp_pkt) {
    return -1;
  }

  // Pop a packet from the queue
  long ret = bpf_map_pop_elem(&mpi_packet_queue, temp_pkt);
  if (ret != 0) {
    // Queue is empty or error
    return -1;
  }

  bpf_printk("Retrieved stored packet: %u bytes", temp_pkt->len);

  // Now you can process the retrieved packet
  // temp_pkt->data[0..temp_pkt->len-1] contains the full packet

  // Parse the stored packet headers
  if (temp_pkt->len >= 14) { // At least Ethernet header
    struct ethhdr *eth = (struct ethhdr *)temp_pkt->data;
    bpf_printk("ETH: proto=0x%x", bpf_ntohs(eth->h_proto));

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP && temp_pkt->len >= 34) {
      struct iphdr *iph = (struct iphdr *)(temp_pkt->data + 14);

      __u32 saddr = iph->saddr;
      __u32 daddr = iph->daddr;
      bpf_printk("Stored IP: %d.%d.%d.%d -> %d.%d.%d.%d",
                 ((unsigned char *)&saddr)[0], ((unsigned char *)&saddr)[1],
                 ((unsigned char *)&saddr)[2], ((unsigned char *)&saddr)[3],
                 ((unsigned char *)&daddr)[0], ((unsigned char *)&daddr)[1],
                 ((unsigned char *)&daddr)[2], ((unsigned char *)&daddr)[3]);

      if (iph->protocol == IPPROTO_UDP && temp_pkt->len >= 42) {
        __u32 ip_hdr_len = iph->ihl * 4;
        struct udphdr *udph =
            (struct udphdr *)(temp_pkt->data + 14 + ip_hdr_len);

        bpf_printk("Stored UDP: %d -> %d", bpf_ntohs(udph->source),
                   bpf_ntohs(udph->dest));

        // Access the MPI payload from stored packet
        __u8 *payload = temp_pkt->data + 14 + ip_hdr_len + 8;
        __u32 payload_len = temp_pkt->len - (14 + ip_hdr_len + 8);

        if (payload_len >= 4) {
          __u32 *mpi_data = (__u32 *)payload;
          __u32 first_int = bpf_ntohl(*mpi_data);
          bpf_printk("Stored MPI first int: %u", first_int);
        }

        // You can now do whatever you want with this stored packet:
        // - Forward it to another interface
        // - Modify it and re-inject
        // - Compare with current incoming packet
        // - Process MPI protocol logic
      }
    }
  }

  return 0;
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
    return XDP_PASS;
  }

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    bpf_printk("XDP: IP header validation failed\n");
    return XDP_ABORTED;
  }

  // Only process UDP packets
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  __u32 ip_hdr_len = iph->ihl * 4;
  struct udphdr *udph = (void *)iph + ip_hdr_len;
  if ((void *)(udph + 1) > data_end) {
    bpf_printk("XDP: UDP header validation failed\n");
    return XDP_ABORTED;
  }

  void *l4_hdr = (void *)iph + ip_hdr_len;
  if (l4_hdr + sizeof(struct udphdr) > data_end)
    return XDP_PASS;

  // Check socket mapping
  socket_id pkt_id = {.src_ip = iph->saddr,
                      .dst_ip = iph->daddr,
                      .src_port = bpf_ntohs(udph->source),
                      .dst_port = bpf_ntohs(udph->dest),
                      .protocol = iph->protocol};

  if (iph->saddr == 0 && iph->daddr == 0) {
    bpf_printk("found a blanch packet");
  }

  tuple_process *value = bpf_map_lookup_elem(&mpi_sockets_map, &pkt_id);
  if (value) {

    void *payload = l4_hdr + sizeof(udph);
    if (payload + sizeof(__u32) <= data_end) {
      __u32 netval = *(__u32 *)payload;
      __u32 val = bpf_ntohl(netval);
      bpf_printk("PAYLOAD INT: %u", val);
      if (val == 2) {
        bpf_printk("MATCH: first payload int == 2");
        // return XDP_TX;
      }
    }

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
    // if (store_full_packet(ctx, 1) < 0) {
    //   bpf_printk("Failed to store MPI packet\n");
    // }
    // bpf_printk("==============\n");
    // process_stored_packets();
    // if (process_stored_packets() < 0) {
    //   break; // No more packets in queue
    // }

    return XDP_PASS;
  }
  //  else {
  //   bpf_printk("XDP: No MPI mapping found for packet\n");
  // }

  // __u32 key = 0;
  // struct full_packet *pkt = bpf_map_lookup_elem(&temp_packet_storage, &key);

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";