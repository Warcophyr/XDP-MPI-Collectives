#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifdef DEBUG
#define bpf_printk(fmt, ...)                                                   \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })
#else
#define bpf_printk(fmt, ...) ({})
#endif

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
  __u32 *head = (__u32 *)bpf_map_lookup_elem(&head_map, &qid);
  __u32 *tail = (__u32 *)bpf_map_lookup_elem(&tail_map, &qid);
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
  __u32 *head = (__u32 *)bpf_map_lookup_elem(&head_map, &qid);
  __u32 *tail = (__u32 *)bpf_map_lookup_elem(&tail_map, &qid);
  if (!head || !tail)
    return -1;

  if ((*head & QUEUE_MASK) == (*tail & QUEUE_MASK))
    return -1; /* empty */

  __u32 flat = qid * QUEUE_SIZE + (*head & QUEUE_MASK);
  packet_info *val = (packet_info *)bpf_map_lookup_elem(&queue_map, &flat);
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