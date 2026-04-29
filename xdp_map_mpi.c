#include "bpf/common.h"

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

    void *payload = l4_hdr + sizeof(struct udphdr);
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