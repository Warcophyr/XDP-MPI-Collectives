/* SPDX-License-Identifier: GPL-2.0
 *
 * XDP BPF program for MPI collectives — AF_XDP (XSK) receive path.
 *
 * Replaces kfunc.bpf.c's XDP_CLONE_PASS with XDP_CLONE_REDIRECT so that
 * the original packet at each hop is delivered directly to the destination
 * rank's AF_XDP socket (XSKMAP[rank]) instead of going through the kernel
 * UDP stack.  Copies continue to travel via XDP_TX exactly as before.
 *
 * Assumptions
 *   - One NIC queue per MPI rank: rank r bound to queue r.
 *   - Ntuple rules steer UDP dst-port (BASE_PORT+r) → queue r (see setup-xsk).
 *   - Userspace populates xsk_map[rank] with the XSK fd for that rank.
 *   - proc_to_address, address_to_proc and num_process are populated by
 *     mpi_init() exactly as in the kfunc path.
 *
 * Clone action encoding (same as kfunc.bpf.c / en_rx.c):
 *   bits [4:0]  = action code  (5=CLONE_PASS, 6=CLONE_TX, 7=CLONE_REDIRECT)
 *   bits [31:5] = copy count
 */

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

#define __XDP_CLONE_PASS     5
#define __XDP_CLONE_TX       6
#define __XDP_CLONE_REDIRECT 7
#define XDP_CLONE_PASS(n)     (((int)(n) << 5) | (int)__XDP_CLONE_PASS)
#define XDP_CLONE_TX(n)       (((int)(n) << 5) | (int)__XDP_CLONE_TX)
#define XDP_CLONE_REDIRECT(n) (((int)(n) << 5) | (int)__XDP_CLONE_REDIRECT)

/* Maximum number of MPI ranks / NIC queues supported. */
#define MAX_RANKS 64

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

/* ── BPF maps ──────────────────────────────────────────────────────────── */

/* Total number of MPI ranks — written by userspace at startup. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} num_process SEC(".maps");

typedef struct socket_id {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8  protocol;
} __attribute__((packed)) socket_id;

typedef struct tuple_process {
  __u32 src_procc;
  __u32 dst_procc;
} tuple_process;

/* 5-tuple → rank pair (used only for consistency with kfunc path). */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, socket_id);
  __type(value, tuple_process);
} address_to_proc SEC(".maps");

/* Rank pair → 5-tuple (used by handle_clone to rewrite forwarded copies). */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, tuple_process);
  __type(value, socket_id);
} proc_to_address SEC(".maps");

/*
 * AF_XDP socket map — one entry per rank / NIC queue.
 * Key   = queue_id (== rank, assuming one queue per rank).
 * Value = XSK socket file descriptor, set by userspace via bpf_map_update_elem.
 *
 * The driver calls xdp_do_redirect() with this map as the target when the BPF
 * program calls bpf_redirect_map(&xsk_map, rank, 0) and returns
 * XDP_CLONE_REDIRECT(N) or a plain XDP_REDIRECT.
 */
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, MAX_RANKS);
  __type(key, __u32);
  __type(value, __u32);
} xsk_map SEC(".maps");

/* ── Helpers ───────────────────────────────────────────────────────────── */

static __always_inline __u16 ip_checksum_xdp(struct iphdr *ip) {
  __u32 sum = 0;
  __u16 *data = (__u16 *)ip;
#pragma unroll
  for (int i = 0; i < 10; i++) {
    if (i == 5)
      continue;
    sum += bpf_ntohs(data[i]);
  }
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return bpf_htons(~sum);
}

static __always_inline int parse_ip_packet(struct xdp_md *ctx,
                                           struct ethhdr **out_eth,
                                           struct iphdr  **out_iph,
                                           struct udphdr **out_udph) {
  void *data     = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return XDP_PASS;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return XDP_PASS;
  if (iph->ihl < 5)
    return XDP_PASS;
  if (iph->protocol != IPPROTO_UDP)
    return XDP_PASS;

  __u32 ip_hdr_len = iph->ihl * 4;
  struct udphdr *udph = (void *)iph + ip_hdr_len;
  if ((void *)(udph + 1) > data_end)
    return XDP_PASS;

  if (out_eth && out_iph && out_udph) {
    *out_eth  = eth;
    *out_iph  = iph;
    *out_udph = udph;
  }
  return -1; /* sentinel: packet parsed successfully */
}

/* Parse the fixed MPI wire header fields from the UDP payload.
 * Returns 0 on success, XDP_PASS if the packet is not a valid MPI frame. */
static __always_inline int parse_mpi_header(void *payload, void *data_end,
                                            int *root_out, int *src_out,
                                            int *dst_out,
                                            MPI_Collective *opcode_out) {
  const int needed = (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2) + sizeof(unsigned long) +
                     sizeof(unsigned long);
  if (payload + needed > data_end)
    return XDP_PASS;

  char magic[4] = {'a', 'a', 'a', 'a'};
#pragma unroll
  for (int i = 0; i < 4; i++)
    __builtin_memcpy(&magic[i], payload + i * sizeof(char), sizeof(char));
  if (magic[0] != 'M' || magic[1] != 'P' || magic[2] != 'I' || magic[3] != '\0')
    return XDP_PASS;

  int root, src, dst;
  MPI_Collective opcode;
  __builtin_memcpy(&root,   (char *)payload + 4,                  sizeof(int));
  __builtin_memcpy(&src,    (char *)payload + 8,                  sizeof(int));
  __builtin_memcpy(&dst,    (char *)payload + 12,                 sizeof(int));
  __builtin_memcpy(&opcode, (char *)payload + 16, sizeof(MPI_Collective));

  *root_out   = bpf_ntohl(root);
  *src_out    = bpf_ntohl(src);
  *dst_out    = bpf_ntohl(dst);
  *opcode_out = bpf_ntohl(opcode);
  return 0;
}

/* ── handle_clone ──────────────────────────────────────────────────────── */
/*
 * Called for every copy (metadata ID ≥ 1).  Rewrites Ethernet, IP, UDP and
 * MPI headers so the copy is steered to the next hop, then returns XDP_TX.
 * The rewritten copy re-enters the NIC RX path and triggers handle_original
 * for the next hop, which redirects it to the correct XSK socket.
 *
 * This function is intentionally identical to kfunc.bpf.c:handle_clone.
 */
static __always_inline int handle_clone(struct xdp_md *ctx,
                                        struct ethhdr *eth,
                                        struct iphdr  *iph,
                                        struct udphdr *udph) {
  void *data_end  = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  if (!iph)
    return XDP_PASS;

  udph = (void *)iph + iph->ihl * 4;
  if ((void *)(udph + 1) > (void *)(long)ctx->data_end)
    return XDP_PASS;

  void *payload = (void *)udph + sizeof(*udph);

  const int needed = (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2) + sizeof(unsigned long) +
                     sizeof(unsigned long);
  if (payload + needed > data_end)
    return XDP_PASS;

  char mpi_header[4] = {'a', 'a', 'a', 'a'};
#pragma unroll
  for (int i = 0; i < 4; i++)
    __builtin_memcpy(&mpi_header[i], payload + i * sizeof(char), sizeof(char));
  if (mpi_header[0] != 'M' || mpi_header[1] != 'P' || mpi_header[2] != 'I' ||
      mpi_header[3] != '\0')
    return XDP_PASS;

  int root, src, dst;
  MPI_Collective opcode;
  __builtin_memcpy(&root,   (char *)payload + 4,  sizeof(int));
  __builtin_memcpy(&src,    (char *)payload + 8,  sizeof(int));
  __builtin_memcpy(&dst,    (char *)payload + 12, sizeof(int));
  __builtin_memcpy(&opcode, (char *)payload + 16, sizeof(MPI_Collective));
  int root_host   = bpf_ntohl(root);
  int src_host    = bpf_ntohl(src);
  int dst_host    = bpf_ntohl(dst);
  MPI_Collective opcode_host = bpf_ntohl(opcode);

  /* Copy ID is stored in the 4-byte metadata region. */
  int iter_copy = 0;
  __builtin_memcpy(&iter_copy, data_meta, sizeof(iter_copy));

  void *src_payload = (char *)payload + 8;
  void *dst_payload = (char *)payload + 12;

  int key = 0;
  int *size_ptr = bpf_map_lookup_elem(&num_process, &key);
  if (!size_ptr)
    return XDP_PASS;
  int size = *size_ptr;

  switch (opcode_host) {
  case MPI_SEND:
    return XDP_PASS;

  case MPI_BCAST_RING:
  case MPI_BCAST_LINEAR: {
    if (root_host == dst_host)
      return XDP_PASS;

    int next = (int)(((unsigned)(dst_host + iter_copy)) % (unsigned)size);
    if (root_host == next)
      return XDP_PASS;

    tuple_process key_proc = {0};
    key_proc.src_procc = dst_host;
    key_proc.dst_procc = next;
    socket_id *fwd = bpf_map_lookup_elem(&proc_to_address, &key_proc);
    if (!fwd)
      return XDP_PASS;

    /* Rewrite Ethernet header. */
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac,       eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest,   ETH_ALEN);
    __builtin_memcpy(eth->h_dest,   tmp_mac,        ETH_ALEN);

    /* Rewrite MPI src/dst fields. */
    int dst_net  = bpf_htonl(dst_host);
    int next_net = bpf_htonl(next);
    __builtin_memcpy(src_payload, &dst_net,  sizeof(int));
    __builtin_memcpy(dst_payload, &next_net, sizeof(int));

    /* Rewrite UDP and IP headers. */
    udph->source = bpf_htons(fwd->src_port);
    udph->dest   = bpf_htons(fwd->dst_port);
    udph->check  = 0;
    iph->saddr   = fwd->src_ip;
    iph->daddr   = fwd->dst_ip;
    iph->check   = ip_checksum_xdp(iph);

    return XDP_TX;
  }

  case MPI_REDUCE:
  default:
    return XDP_PASS;
  }
}

/* ── handle_original ───────────────────────────────────────────────────── */
/*
 * Called on the first arrival of an MPI packet (no metadata prefix).
 *
 * For every collective that needs delivery, the original is redirected to
 * the destination rank's AF_XDP socket via bpf_redirect_map() +
 * XDP_CLONE_REDIRECT(N).  The driver then:
 *   1. Calls xdp_do_redirect() to hand the original frame to the XSK ring.
 *   2. Creates N copies and dispatches them back through handle_clone().
 *
 * For copies arriving after an XDP_TX re-entry (linear broadcast, non-root
 * hop), we issue a plain bpf_redirect_map() which returns XDP_REDIRECT —
 * no further cloning is needed.
 */
static __always_inline int handle_original(struct xdp_md *ctx,
                                           struct ethhdr *eth,
                                           struct iphdr  *iph,
                                           struct udphdr *udph) {
  void *data_end = (void *)(long)ctx->data_end;

  if (!iph)
    return XDP_PASS;

  udph = (void *)iph + iph->ihl * 4;
  if ((void *)(udph + 1) > (void *)(long)ctx->data_end)
    return XDP_PASS;

  void *payload = (void *)udph + sizeof(*udph);

  int root_host, src_host, dst_host;
  MPI_Collective opcode_host;
  int rc = parse_mpi_header(payload, data_end,
                            &root_host, &src_host, &dst_host, &opcode_host);
  if (rc != 0)
    return XDP_PASS;

  int key = 0;
  int *size_ptr = bpf_map_lookup_elem(&num_process, &key);
  if (!size_ptr)
    return XDP_ABORTED;
  int size = *size_ptr;

  switch (opcode_host) {

  case MPI_SEND:
    /*
     * Point-to-point: redirect directly to the destination rank's XSK socket.
     * No cloning needed.
     */
    return bpf_redirect_map(&xsk_map, dst_host, 0);

  case MPI_BCAST_RING: {
    if (root_host == dst_host)
      return XDP_PASS; /* root's own packet — pass to root's kernel socket */

    /*
     * Set the redirect target for the original packet, then return
     * XDP_CLONE_REDIRECT(1).  The driver delivers the original to
     * xsk_map[dst_host] and creates 1 copy for handle_clone to forward.
     */
    bpf_redirect_map(&xsk_map, dst_host, 0);
    bpf_printk("handle_original: root=%d dst=%d size=%d iter_copy=%d\n",
               root_host, dst_host, size, 0);
    return XDP_CLONE_REDIRECT(1);
  }

  case MPI_BCAST_LINEAR: {
    if (root_host == dst_host)
      return XDP_PASS; /* root's own packet */

    if (root_host == src_host) {
      /*
       * Root's initial send: redirect original to rank 1 (dst_host) and
       * fan out `size` copies so handle_clone steers them to ranks 2..N-1.
       */
      bpf_redirect_map(&xsk_map, dst_host, 0);
      return XDP_CLONE_REDIRECT(size);
    }

    /*
     * A copy re-entered the NIC after an XDP_TX from handle_clone.
     * It has already been rewritten to target this rank (dst_host).
     * Redirect directly — no further cloning.
     */
    return bpf_redirect_map(&xsk_map, dst_host, 0);
  }

  case MPI_REDUCE:
  default:
    return XDP_PASS;
  }
}

/* ── XDP entry point ───────────────────────────────────────────────────── */

SEC("xdp")
int mpi_xsk(struct xdp_md *ctx) {
  struct ethhdr *eth;
  struct iphdr  *iph;
  struct udphdr *udph;

  int ret = parse_ip_packet(ctx, &eth, &iph, &udph);
  if (ret >= 0)
    return ret;

  /* Only process packets from the remote machine (GRECALE_IP 192.168.101.2). */
  if (iph->saddr != bpf_htonl(3232261378U))
    return XDP_PASS;

  /*
   * Dispatch on metadata presence:
   *   data_meta + 4 <= data  →  copy (ID ≥ 1) written by the driver
   *   otherwise              →  original (ID = 0, no metadata)
   */
  if ((void *)(long)ctx->data_meta + sizeof(__u32) <= (void *)(long)ctx->data)
    return handle_clone(ctx, eth, iph, udph);
  else
    return handle_original(ctx, eth, iph, udph);
}

char LICENSE[] SEC("license") = "GPL";
