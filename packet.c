#include "packet.h"

// Compute IPv4 header checksum (standard internet checksum)
static uint16_t ip_checksum(void *vdata, size_t length) {
  char *data = vdata;
  uint32_t acc = 0xffff;

  // Handle complete 16‑bit blocks…
  for (size_t i = 0; i + 1 < length; i += 2) {
    uint16_t word;
    memcpy(&word, data + i, 2);
    acc += ntohs(word);
    if (acc > 0xffff) {
      acc -= 0xffff;
    }
  }

  // Handle any left‑over byte
  if (length & 1) {
    uint16_t word = 0;
    memcpy(&word, data + length - 1, 1);
    acc += ntohs(word);
    if (acc > 0xffff) {
      acc -= 0xffff;
    }
  }

  // “Fold” and invert
  return htons(~acc & 0xffff);
}

/**
 * build_eth_ipv4_packet()
 * -----------------------
 * Constructs an Ethernet + IPv4 packet around a payload.
 *
 * @payload:      pointer to your payload bytes
 * @payload_len:  number of payload bytes
 * @out_packet:   receives a malloc’d buffer containing eth+IP+payload
 * @out_len:      receives total length of that buffer
 *
 * Returns 0 on success (you must free(*out_packet)), or -1 on error.
 */
int build_eth_ipv4_packet(const uint8_t *payload, size_t payload_len,
                          uint8_t **out_packet, size_t *out_len) {
  if (!payload || !out_packet || !out_len)
    return -1;

  // Ethernet header + IPv4 header (no options) + payload
  size_t eth_hdr_len = sizeof(struct ether_header);
  size_t ip_hdr_len = sizeof(struct iphdr);
  size_t total_len = eth_hdr_len + ip_hdr_len + payload_len;

  uint8_t *buf = malloc(total_len);
  if (!buf)
    return -1;
  memset(buf, 0, total_len);

  // 1) Ethernet header
  struct ether_header *eth = (void *)buf;
  // dst = FF:FF:FF:FF:FF:FF (broadcast)
  memset(eth->ether_dhost, 0xFF, ETH_ALEN);
  // src = 12:34:56:78:9A:BC
  uint8_t src_mac[ETH_ALEN] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
  memcpy(eth->ether_shost, src_mac, ETH_ALEN);
  eth->ether_type = htons(ETHERTYPE_IP);

  // 2) IPv4 header
  struct iphdr *ip = (void *)(buf + eth_hdr_len);
  ip->version = 4;
  ip->ihl = ip_hdr_len / 4; // 5 words = 20 bytes
  ip->tos = 0;
  ip->tot_len = htons(ip_hdr_len + payload_len);
  ip->id = htons(0x1234);
  ip->frag_off = htons(0x4000); // DF set
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP; // change to IPPROTO_TCP/UDP as needed
  // src = 192.168.0.1, dst = 192.168.0.2
  ip->saddr = inet_addr("192.168.0.1");
  ip->daddr = inet_addr("192.168.0.2");
  ip->check = 0;
  ip->check = ip_checksum(ip, ip_hdr_len);

  // 3) Copy payload
  memcpy(buf + eth_hdr_len + ip_hdr_len, payload, payload_len);

  *out_packet = buf;
  *out_len = total_len;
  return 0;
}

// Example usage:
// #ifdef DEMO_MAIN
// int main(void) {
//   const char test_payload[] = "hello, world!";
//   uint8_t *pkt;
//   size_t pkt_len;

//   if (build_eth_ipv4_packet((void *)test_payload, sizeof(test_payload) - 1,
//                             &pkt, &pkt_len) == 0) {
//     printf("Built packet of %zu bytes\n", pkt_len);
//     // You can now use pkt/pkt_len for bpf_prog_test_run_opts()
//     free(pkt);
//   } else {
//     fprintf(stderr, "Failed to build packet\n");
//   }
//   return 0;
// }
// #endif
