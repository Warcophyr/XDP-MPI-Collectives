/* SPDX-License-Identifier: GPL-2.0 */
/* BPF side of the A-XDP TX descriptor: what a program stamps into its own
 * metadata area to ask the NIC for a TX offload.
 *
 * A copy of mellanox-clone-xdp/examples/inline-clone/axdp_tx.h, which is where
 * it is documented, kept here because that lives in another repository. The
 * driver side is mlx5/core/en/xdp.h; the three of them have to agree.
 */
#ifndef __AXDP_TX_H__
#define __AXDP_TX_H__

/* Three words at data_meta:
 *
 *   word 0  flow_table_metadata tag, network order
 *   word 1  inline_hdr_size, plus AXDP_TX_REPLACE in the top bit
 *   word 2  AXDP_TX_MAGIC
 *
 * The magic makes the descriptor opt-in: without it the driver cannot tell a
 * stamped descriptor from unrelated metadata, and would read whatever is in
 * word 1 as a length.
 */
#define AXDP_TX_MAGIC 0xa7d9c0deu
#define AXDP_TX_DESC_LEN 12
#define AXDP_TX_MAX_INLINE 64

/* Without this the NIC prepends the header and the frame comes out longer.
 * With it the driver leaves the packet's first hdr_len bytes out of the DMA, so
 * the header stands in for them and the frame keeps its length.
 */
#define AXDP_TX_REPLACE 0x80000000u

/* Bytes of metadata the driver puts in front of a *copy* of a packet, holding
 * the 1-based copy index. Its absence is what identifies an original.
 */
#define AXDP_CLONE_META_SIZE 4

/* Stamp the descriptor. @hdr_len bytes of inline header must already sit at
 * data_meta + AXDP_TX_DESC_LEN. Returns 0, or -1 if it does not fit.
 *
 * A stamp is the only thing that makes the driver apply a TX offload; an
 * unstamped buffer is transmitted as it is.
 *
 * One bounds check and one place that reads data_meta, on purpose: a helper
 * that re-read it to set a flag afterwards would hand the verifier a pointer
 * with no proven range.
 */
static __always_inline int __axdp_stamp(struct xdp_md *ctx, __u32 tag,
                                        __u32 hdr_len, __u32 flags) {
  __u32 *desc = (void *)(long)ctx->data_meta;
  void *data = (void *)(long)ctx->data;

  if (hdr_len > AXDP_TX_MAX_INLINE)
    return -1;
  if ((void *)desc + AXDP_TX_DESC_LEN + hdr_len > data)
    return -1;

  desc[0] = tag;
  desc[1] = hdr_len | flags;
  desc[2] = AXDP_TX_MAGIC;
  return 0;
}

/* Push: the NIC puts the header in front of the packet, which stays where it
 * is, and the frame comes out @hdr_len bytes longer.
 */
static __always_inline int axdp_stamp_tx(struct xdp_md *ctx, __u32 tag,
                                         __u32 hdr_len) {
  return __axdp_stamp(ctx, tag, hdr_len, 0);
}

/* Replace: the header stands in for the packet's first @hdr_len bytes, which
 * the driver leaves out of the DMA, so the frame keeps its length.
 */
static __always_inline int axdp_stamp_tx_replace(struct xdp_md *ctx, __u32 tag,
                                                 __u32 hdr_len) {
  return __axdp_stamp(ctx, tag, hdr_len, AXDP_TX_REPLACE);
}

#endif /* __AXDP_TX_H__ */
