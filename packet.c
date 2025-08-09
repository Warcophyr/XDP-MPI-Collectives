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

static uint16_t ipv4_checksum(void *buffer, int hdr_len) {
  uint16_t *buf = (uint16_t *)buffer;
  uint32_t sum = 0;
  int count = hdr_len / 2; // number of 16-bit words

  // Sum all 16-bit words
  for (int i = 0; i < count; i++) {
    sum += ntohs(buf[i]); // convert to host order before summing
  }

  // If hdr_len is odd (usually not), handle last byte padded with zero
  if (hdr_len & 1) {
    uint8_t *b = (uint8_t *)buffer;
    sum += b[hdr_len - 1] << 8; // pad low byte with zero
  }

  // Add carries
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // One's complement and return in network byte order
  return htons(~sum);
}

static uint16_t udp_checksum(void *buffer, int len) {
  uint16_t *buf = (uint16_t *)buffer;
  uint32_t sum = 0;

  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }

  // If there's a byte left, add it (padding with zero)
  if (len == 1) {
    sum += *((uint8_t *)buf);
  }

  // Add carry bits
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  // One's complement
  return (uint16_t)(~sum);
}

// static uint16_t ip_checksum(const void *vdata, size_t length) {
//   const uint8_t *data = (const uint8_t *)vdata;
//   uint32_t acc = 0;

//   /* Sum 16-bit words in network order (big-endian) */
//   for (size_t i = 0; i + 1 < length; i += 2) {
//     acc += ((uint16_t)data[i] << 8) | (uint16_t)data[i + 1];
//   }

//   /* If there's a leftover odd byte, pad it as the high-order byte */
//   if (length & 1) {
//     acc += ((uint16_t)data[length - 1] << 8);
//   }

//   /* Fold carries */
//   while (acc >> 16)
//     acc = (acc & 0xFFFF) + (acc >> 16);

//   uint16_t checksum = (uint16_t)~acc & 0xFFFF;
//   return htons(checksum); /* return in network byte order */
// }

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
