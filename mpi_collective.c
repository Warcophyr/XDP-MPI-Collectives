#define _GNU_SOURCE
#include "mpi_collective.h"
size_t WORD_SIZE = 1;
MPI_process_info *MPI_PROCESS = NULL;
// Global peer address table
struct sockaddr_in *peer_addrs = NULL;
int udp_socket_fd = -1;

int extract_5tuple(int sockfd, struct socket_id *id) {
  struct sockaddr_in local_addr;
  socklen_t addr_len = sizeof(struct sockaddr_in);

  if (getsockname(sockfd, (struct sockaddr *)&local_addr, &addr_len) == -1) {
    perror("getsockname");
    return -1;
  }

  id->src_ip = local_addr.sin_addr.s_addr;
  id->src_port = ntohs(local_addr.sin_port);
  id->protocol = IPPROTO_UDP; // 17 for UDP

  // For UDP monitoring, we want to capture both send and receive patterns
  // Set dst_ip to localhost since all communication is local
  inet_pton(AF_INET, "127.0.0.1", &id->dst_ip);
  id->dst_port = 0; // Will be filled when we know the peer

  return 0;
}

int create_udp_socket(int port) {
  int socket_fd;
  struct sockaddr_in addr;

  socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_fd < 0) {
    perror("socket failed\n");
    exit(EXIT_FAILURE);
  }

  int opt = 1;
  struct timeval tv_out;
  tv_out.tv_sec = 5;
  tv_out.tv_usec = 0;
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    perror("setsocketopt SO_REUSEADDR\n");
  }
  if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) <
      0) {
    perror("setsocketopt SO_RCVTIMEO\n");
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind failed\n");
    exit(EXIT_FAILURE);
  }

  return socket_fd;
}

MPI_process_info *mpi_init(int rank, int mpi_sockets_map_fd,
                           int mpi_send_map_fd) {
  MPI_process_info *mpi_process_info =
      (MPI_process_info *)malloc(sizeof(MPI_process_info));
  if (mpi_process_info == NULL) {
    perror("malloc failed\n");
    exit(EXIT_FAILURE);
  }
  mpi_process_info->rank = rank;

  // Create UDP socket for this process
  udp_socket_fd = create_udp_socket(BASE_PORT + rank);

  // Store the single UDP socket - maintaining compatibility with existing
  // structure
  mpi_process_info->socket_fd = (int *)malloc(WORD_SIZE * sizeof(int));
  memset(mpi_process_info->socket_fd, -1, WORD_SIZE * sizeof(int));
  mpi_process_info->socket_fd[0] = udp_socket_fd; // Store UDP socket at index 0

  // Create peer address table for UDP communication
  peer_addrs =
      (struct sockaddr_in *)malloc(WORD_SIZE * sizeof(struct sockaddr_in));

  for (int i = 0; i < WORD_SIZE; i++) {
    if (i == rank) {
      memset(&peer_addrs[i], 0, sizeof(struct sockaddr_in));
      continue;
    }

    peer_addrs[i].sin_family = AF_INET;
    peer_addrs[i].sin_port = htons(BASE_PORT + i);
    inet_pton(AF_INET, "127.0.0.1", &peer_addrs[i].sin_addr);
  }

  // Update BPF map with socket information for each potential communication
  // pair
  if (mpi_sockets_map_fd >= 0) {
    // Add entries for this process as both sender and receiver
    for (int peer = 0; peer < WORD_SIZE; peer++) {
      if (peer == rank)
        continue;

      // Entry for outgoing traffic (this process -> peer)
      socket_id out_socket_map;
      out_socket_map.src_ip = inet_addr("127.0.0.1");
      out_socket_map.dst_ip = inet_addr("127.0.0.1");
      out_socket_map.src_port = BASE_PORT + rank;
      out_socket_map.dst_port = BASE_PORT + peer;
      out_socket_map.protocol = IPPROTO_UDP;

      tuple_process value = {0};

      value.src_procc = rank;
      value.dst_procc = peer;

      if (bpf_map_update_elem(mpi_sockets_map_fd, &out_socket_map, &value,
                              BPF_ANY) != 0) {
        printf("fail update map mpi_sockets_map for outgoing %d->%d\n", rank,
               peer);
      }

      // Entry for incoming traffic (peer -> this process)
      socket_id in_socket_map;
      in_socket_map.src_ip = inet_addr("127.0.0.1");
      in_socket_map.dst_ip = inet_addr("127.0.0.1");
      in_socket_map.src_port = BASE_PORT + peer;
      in_socket_map.dst_port = BASE_PORT + rank;
      in_socket_map.protocol = IPPROTO_UDP;

      value.src_procc = peer;
      value.dst_procc = rank;

      if (bpf_map_update_elem(mpi_sockets_map_fd, &in_socket_map, &value,
                              BPF_ANY) != 0) {
        printf("fail update map mpi_sockets_map for incoming %d->%d\n", peer,
               rank);
      }
    }
  }
  if (mpi_send_map_fd >= 0) {
    // Add entries for this process as both sender and receiver
    for (int peer = 0; peer < WORD_SIZE; peer++) {
      if (peer == rank)
        continue;

      // Entry for outgoing traffic (this process -> peer)
      socket_id out_socket_map;
      out_socket_map.src_ip = inet_addr("127.0.0.1");
      out_socket_map.dst_ip = inet_addr("127.0.0.1");
      out_socket_map.src_port = BASE_PORT + rank;
      out_socket_map.dst_port = BASE_PORT + peer;
      out_socket_map.protocol = IPPROTO_UDP;

      tuple_process value = {0};

      value.src_procc = rank;
      value.dst_procc = peer;

      if (bpf_map_update_elem(mpi_send_map_fd, &value, &out_socket_map,
                              BPF_ANY) != 0) {
        printf("fail update map mpi_sockets_map for outgoing %d->%d\n", rank,
               peer);
      }

      // Entry for incoming traffic (peer -> this process)
      socket_id in_socket_map;
      in_socket_map.src_ip = inet_addr("127.0.0.1");
      in_socket_map.dst_ip = inet_addr("127.0.0.1");
      in_socket_map.src_port = BASE_PORT + peer;
      in_socket_map.dst_port = BASE_PORT + rank;
      in_socket_map.protocol = IPPROTO_UDP;

      value.src_procc = peer;
      value.dst_procc = rank;

      if (bpf_map_update_elem(mpi_send_map_fd, &value, &in_socket_map,
                              BPF_ANY) != 0) {
        printf("fail update map mpi_sockets_map for incoming %d->%d\n", peer,
               rank);
      }
    }
  }

  // Brief synchronization delay
  sleep(1);
  return mpi_process_info;
}

int datatype_size_in_bytes(int count, MPI_Datatype datatype) {
  int res = -1;
  switch (datatype) {
  case MPI_CHAR:
    res = count * sizeof(char);
    break;
  case MPI_SIGNED_CHAR:
    res = count * sizeof(signed char);
    break;
  case MPI_UNSIGNED_CHAR:
    res = count * sizeof(unsigned char);
    break;
  case MPI_SHORT:
    res = count * sizeof(short);
    break;
  case MPI_UNSIGNED_SHORT:
    res = count * sizeof(unsigned short);
    break;
  case MPI_INT:
    res = count * sizeof(int);
    break;
  case MPI_UNSIGNED:
    res = count * sizeof(unsigned);
    break;
  case MPI_LONG:
    res = count * sizeof(long);
    break;
  case MPI_UNSIGNED_LONG:
    res = count * sizeof(unsigned long);
    break;
  case MPI_LONG_LONG:
    res = count * sizeof(long long);
    break;
  case MPI_UNSIGNED_LONG_LONG:
    res = count * sizeof(unsigned long long);
    break;
  case MPI_FLOAT:
    res = count * sizeof(float);
    break;
  case MPI_DOUBLE:
    res = count * sizeof(double);
    break;
  case MPI_LONG_DOUBLE:
    res = count * sizeof(long double);
    break;
  case MPI_C_BOOL:
    res = count * sizeof(bool);
    break;
  case MPI_WCHAR:
    res = count * sizeof(wchar_t);
    break;
  default:
    break;
  }
  return res;
}

int mpi_send(const void *buf, int count, MPI_Datatype datatype, int dest,
             int tag) {
  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    return -1;
  }

  // Create message with tag header
  int total_size = sizeof(int) + size;
  void *message = malloc(total_size);
  if (!message) {
    perror("malloc failed");
    return -1;
  }

  // Add tag to message header
  void *tag_send = message;
  generic_hton(tag_send, &tag, sizeof(int), 1);

  // Add data payload
  void *buf_send = (char *)message + sizeof(int);
  switch (datatype) {
  case MPI_CHAR:
    generic_hton(buf_send, buf, sizeof(char), count);
    break;
  case MPI_SIGNED_CHAR:
    generic_hton(buf_send, buf, sizeof(signed char), count);
    break;
  case MPI_UNSIGNED_CHAR:
    generic_hton(buf_send, buf, sizeof(unsigned char), count);
    break;
  case MPI_SHORT:
    generic_hton(buf_send, buf, sizeof(short), count);
    break;
  case MPI_UNSIGNED_SHORT:
    generic_hton(buf_send, buf, sizeof(unsigned short), count);
    break;
  case MPI_INT:
    generic_hton(buf_send, buf, sizeof(int), count);
    break;
  case MPI_UNSIGNED:
    generic_hton(buf_send, buf, sizeof(unsigned), count);
    break;
  case MPI_LONG:
    generic_hton(buf_send, buf, sizeof(long), count);
    break;
  case MPI_UNSIGNED_LONG:
    generic_hton(buf_send, buf, sizeof(unsigned long), count);
    break;
  case MPI_LONG_LONG:
    generic_hton(buf_send, buf, sizeof(long long), count);
    break;
  case MPI_UNSIGNED_LONG_LONG:
    generic_hton(buf_send, buf, sizeof(unsigned long long), count);
    break;
  case MPI_FLOAT:
    generic_hton(buf_send, buf, sizeof(float), count);
    break;
  case MPI_DOUBLE:
    generic_hton(buf_send, buf, sizeof(double), count);
    break;
  case MPI_LONG_DOUBLE:
    generic_hton(buf_send, buf, sizeof(long double), count);
    break;
  case MPI_C_BOOL:
    generic_hton(buf_send, buf, sizeof(bool), count);
    break;
  case MPI_WCHAR:
    generic_hton(buf_send, buf, sizeof(wchar_t), count);
    break;
  default:
    free(message);
    return -1;
  }

  // Send UDP message using the global socket and peer address table
  ssize_t sent =
      sendto(udp_socket_fd, message, total_size, 0,
             (struct sockaddr *)&peer_addrs[dest], sizeof(struct sockaddr_in));

  free(message);

  if (sent != total_size) {
    perror("sendto failed");
    return -1;
  }

  return count;
}

void print_mpi_message(void *buf, int length, MPI_Datatype datatype) {
  switch (datatype) {
  case MPI_CHAR:
    char *arr_c = (char *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%c", arr_c[i]);
    }
    printf("\n");
    break;
  case MPI_SIGNED_CHAR:
    signed char *arr_sc = (signed char *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%hhd", arr_sc[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED_CHAR:
    unsigned char *arr_uc = (unsigned char *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%hhu", arr_uc[i]);
    }
    printf("\n");
    break;
  case MPI_SHORT:
    short *arr_s = (short *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%hd ", arr_s[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED_SHORT:
    unsigned short *arr_us = (unsigned short *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%hu ", arr_us[i]);
    }
    printf("\n");
    break;
  case MPI_INT:
    int *arr_i = (int *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%d ", arr_i[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED:
    unsigned *arr_u = (unsigned *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%u ", arr_u[i]);
    }
    printf("\n");
    break;
  case MPI_LONG:
    long *arr_l = (long *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%ld ", arr_l[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED_LONG:
    unsigned long *arr_ul = (unsigned long *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%lu ", arr_ul[i]);
    }
    printf("\n");
    break;
  case MPI_LONG_LONG:
    long long *arr_ll = (long long *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%lld ", arr_ll[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED_LONG_LONG:
    unsigned long long *arr_ull = (unsigned long long *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%llu ", arr_ull[i]);
    }
    printf("\n");
    break;
  case MPI_FLOAT:
    float *arr_f = (float *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%f ", arr_f[i]);
    }
    printf("\n");
    break;
  case MPI_DOUBLE:
    double *arr_d = (double *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%f ", arr_d[i]);
    }
    printf("\n");
    break;
  case MPI_LONG_DOUBLE:
    long double *arr_ld = (long double *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%Lf ", arr_ld[i]);
    }
    printf("\n");
    break;
  case MPI_C_BOOL:
    bool *arr_b = (bool *)buf;
    if (arr_b[0]) {
      printf("True\n");
    } else {
      printf("False\n");
    }
    break;
  case MPI_WCHAR:
    wchar_t *arr_wc = (wchar_t *)buf;
    for (size_t i = 0; i < length; i++) {
      wprintf(L"%lc ", arr_wc[i]);
    }
    wprintf(L"\n");
    break;
  default:
    break;
  }
}

int mpi_recv(void *buf, int count, MPI_Datatype datatype, int source, int tag) {
  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    return -1;
  }

  int total_size = sizeof(int) + size;
  void *message = malloc(total_size);
  if (!message) {
    perror("malloc failed");
    return -1;
  }

  struct sockaddr_in sender_addr;
  socklen_t sender_len = sizeof(sender_addr);

  // Receive UDP message using the global socket
  ssize_t received = recvfrom(udp_socket_fd, message, total_size, 0,
                              (struct sockaddr *)&sender_addr, &sender_len);

  if (received < sizeof(int)) {
    free(message);
    printf("failed recv - message too short\n");
    return -1;
  }

  // Extract tag from message header
  int tag_int;
  generic_ntoh(&tag_int, message, sizeof(int), 1);

  // Extract data payload
  void *buf_recv = (char *)message + sizeof(int);
  int data_size = received - sizeof(int);

  if (data_size != size) {
    free(message);
    printf("received data size mismatch\n");
    return -1;
  }

  // Convert from network byte order to host byte order
  switch (datatype) {
  case MPI_CHAR: {
    generic_ntoh(buf, buf_recv, sizeof(char), count);
    char *buf_char = (char *)buf;
    buf_char[count] = '\0';
  } break;
  case MPI_SIGNED_CHAR: {
    generic_ntoh(buf, buf_recv, sizeof(signed char), count);
    signed char *buf_char = (signed char *)buf;
    buf_char[count] = '\0';
  } break;
  case MPI_UNSIGNED_CHAR: {
    generic_ntoh(buf, buf_recv, sizeof(unsigned char), count);
    unsigned char *buf_char = (unsigned char *)buf;
    buf_char[count] = '\0';
  } break;
  case MPI_SHORT: {
    generic_ntoh(buf, buf_recv, sizeof(short), count);
  } break;
  case MPI_UNSIGNED_SHORT: {
    generic_ntoh(buf, buf_recv, sizeof(unsigned short), count);
  } break;
  case MPI_INT: {
    generic_ntoh(buf, buf_recv, sizeof(int), count);
  } break;
  case MPI_UNSIGNED: {
    generic_ntoh(buf, buf_recv, sizeof(unsigned), count);
  } break;
  case MPI_LONG: {
    generic_ntoh(buf, buf_recv, sizeof(long), count);
  } break;
  case MPI_UNSIGNED_LONG: {
    generic_ntoh(buf, buf_recv, sizeof(unsigned long), count);
  } break;
  case MPI_LONG_LONG: {
    generic_ntoh(buf, buf_recv, sizeof(long long), count);
  } break;
  case MPI_UNSIGNED_LONG_LONG: {
    generic_ntoh(buf, buf_recv, sizeof(unsigned long long), count);
  } break;
  case MPI_FLOAT: {
    generic_ntoh(buf, buf_recv, sizeof(float), count);
  } break;
  case MPI_DOUBLE: {
    generic_ntoh(buf, buf_recv, sizeof(double), count);
  } break;
  case MPI_LONG_DOUBLE: {
    generic_ntoh(buf, buf_recv, sizeof(long double), count);
  } break;
  case MPI_C_BOOL: {
    generic_ntoh(buf, buf_recv, sizeof(bool), count);
  } break;
  case MPI_WCHAR: {
    generic_ntoh(buf, buf_recv, sizeof(wchar_t), count);
    wchar_t *buf_char = (wchar_t *)buf;
    buf_char[count] = L'\0';
  } break;
  default:
    free(message);
    return -1;
  }

  free(message);
  return count;
}

int mpi_send_raw(const void *buf, int count, MPI_Datatype datatype, int dest,
                 int tag, packet_info *value) {

  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    return -1;
  }

  // Create message with tag header (same as regular mpi_send)
  int payload_size = sizeof(int) + size;
  void *message = malloc(payload_size);
  if (!message) {
    perror("malloc failed");
    return -1;
  }

  // Add tag to message header
  void *tag_send = message;
  generic_hton(tag_send, &tag, sizeof(int), 1);

  // Add data payload (same conversion logic as mpi_send)
  void *buf_send = (char *)message + sizeof(int);
  switch (datatype) {
  case MPI_CHAR:
    generic_hton(buf_send, buf, sizeof(char), count);
    break;
  case MPI_SIGNED_CHAR:
    generic_hton(buf_send, buf, sizeof(signed char), count);
    break;
  case MPI_UNSIGNED_CHAR:
    generic_hton(buf_send, buf, sizeof(unsigned char), count);
    break;
  case MPI_SHORT:
    generic_hton(buf_send, buf, sizeof(short), count);
    break;
  case MPI_UNSIGNED_SHORT:
    generic_hton(buf_send, buf, sizeof(unsigned short), count);
    break;
  case MPI_INT:
    generic_hton(buf_send, buf, sizeof(int), count);
    break;
  case MPI_UNSIGNED:
    generic_hton(buf_send, buf, sizeof(unsigned), count);
    break;
  case MPI_LONG:
    generic_hton(buf_send, buf, sizeof(long), count);
    break;
  case MPI_UNSIGNED_LONG:
    generic_hton(buf_send, buf, sizeof(unsigned long), count);
    break;
  case MPI_LONG_LONG:
    generic_hton(buf_send, buf, sizeof(long long), count);
    break;
  case MPI_UNSIGNED_LONG_LONG:
    generic_hton(buf_send, buf, sizeof(unsigned long long), count);
    break;
  case MPI_FLOAT:
    generic_hton(buf_send, buf, sizeof(float), count);
    break;
  case MPI_DOUBLE:
    generic_hton(buf_send, buf, sizeof(double), count);
    break;
  case MPI_LONG_DOUBLE:
    generic_hton(buf_send, buf, sizeof(long double), count);
    break;
  case MPI_C_BOOL:
    generic_hton(buf_send, buf, sizeof(bool), count);
    break;
  case MPI_WCHAR:
    generic_hton(buf_send, buf, sizeof(wchar_t), count);
    break;
  default:
    free(message);
    return -1;
  }

  // Get socket info for the destination process
  tuple_process key = {MPI_PROCESS->rank, dest};
  socket_id socket_info = {0};

  if (bpf_map_lookup_elem(EBPF_INFO.mpi_send_map_fd, &key, &socket_info) != 0) {
    printf("Failed to lookup socket info for rank %d -> %d\n",
           MPI_PROCESS->rank, dest);
    free(message);
    return -1;
  }

  // Extract MAC addresses from the packet_info value parameter
  uint8_t dst_mac[ETH_ALEN];
  uint8_t src_mac[ETH_ALEN];

  // Copy source MAC from packet_info as destination MAC for our packet
  memcpy(dst_mac, &value->eth_hdr[6],
         ETH_ALEN); // Source MAC from received packet
  // Copy destination MAC from packet_info as source MAC for our packet
  memcpy(src_mac, &value->eth_hdr[0],
         ETH_ALEN); // Dest MAC from received packet

  // Build the complete packet
  size_t eth_hdr_len = sizeof(struct ether_header);
  size_t ip_hdr_len = sizeof(struct iphdr);
  size_t udp_hdr_len = sizeof(struct udphdr);
  size_t total_len = eth_hdr_len + ip_hdr_len + udp_hdr_len + payload_size;

  uint8_t *packet = malloc(total_len);
  if (!packet) {
    free(message);
    return -1;
  }
  memset(packet, 0, total_len);

  // 1) Ethernet header
  struct ether_header *eth = (struct ether_header *)packet;
  memcpy(eth->ether_dhost, dst_mac, ETH_ALEN); // Use extracted dest MAC
  memcpy(eth->ether_shost, src_mac, ETH_ALEN); // Use extracted source MAC
  eth->ether_type = htons(ETHERTYPE_IP);

  // 2) IPv4 header
  struct iphdr *ip = (struct iphdr *)(packet + eth_hdr_len);
  ip->version = 4;
  ip->ihl = ip_hdr_len / 4; // 5 words = 20 bytes
  ip->tos = 0;
  ip->tot_len = htons(ip_hdr_len + udp_hdr_len + payload_size);
  ip->id = htons(0x1234);
  ip->frag_off = htons(0x4000); // DF set
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = socket_info.src_ip; // Use socket info from BPF map
  ip->daddr = socket_info.dst_ip; // Use socket info from BPF map
  ip->check = 0;
  ip->check = ip_checksum(ip, ip_hdr_len);

  // 3) UDP header
  struct udphdr *udp = (struct udphdr *)(packet + eth_hdr_len + ip_hdr_len);
  udp->source = htons(socket_info.src_port);
  udp->dest = htons(socket_info.dst_port);
  udp->len = htons(udp_hdr_len + payload_size);
  udp->check = 0; // UDP checksum is optional for IPv4
  // udp->check = udp_checksum(
  //     udp, udp_hdr_len + payload_size);

  // 4) Copy MPI payload (tag + data)
  memcpy(packet + eth_hdr_len + ip_hdr_len + udp_hdr_len, message,
         payload_size);

  // Create raw socket for sending
  int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (raw_socket < 0) {
    perror("Failed to create raw socket");
    free(message);
    free(packet);
    return -1;
  }

  // Determine the interface to send on
  // You can get this from the ingress_ifindex in packet_info
  int ifindex = value->ingress_ifindex;
  if (ifindex == 0) {
    // Fallback to loopback interface if no interface specified
    ifindex = if_nametoindex("lo");
    if (ifindex == 0) {
      perror("Failed to get interface index");
      close(raw_socket);
      free(message);
      free(packet);
      return -1;
    }
  }

  // Prepare sockaddr_ll for raw socket
  struct sockaddr_ll socket_address;
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons(ETH_P_ALL);
  socket_address.sll_ifindex = ifindex;
  socket_address.sll_halen = ETH_ALEN;
  memcpy(socket_address.sll_addr, dst_mac, ETH_ALEN);

  printf("Sending raw packet (rank %d -> %d) on interface %d...\n",
         MPI_PROCESS->rank, dest, ifindex);

  // Send the complete Ethernet frame via raw socket
  ssize_t sent =
      sendto(raw_socket, packet, total_len, 0,
             (struct sockaddr *)&socket_address, sizeof(socket_address));

  // ssize_t sent_ =
  //     sendto(udp_socket_fd, message, payload_size, 0,
  //            (struct sockaddr *)&peer_addrs[dest], sizeof(struct
  //            sockaddr_in));

  close(raw_socket);

  if (sent != total_len) {
    perror("Raw socket sendto failed");
    printf("Sent %zd bytes out of %zu\n", sent, total_len);
    free(message);
    free(packet);
    return -1;
  }

  printf("Successfully sent %zd bytes via raw socket\n", sent);

  free(message);
  free(packet);
  return count;
}

int mpi_barrier(void) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;
  int msg = 1;

  int parent = (rank - 1) / 2;
  int left = 2 * rank + 1;
  int right = 2 * rank + 2;

  // Phase 1: Wait for messages from children
  if (left < size)
    mpi_recv(&msg, 1, MPI_INT, left, 0);
  if (right < size)
    mpi_recv(&msg, 1, MPI_INT, right, 0);

  // Phase 2: Notify parent
  if (rank != 0)
    mpi_send(&msg, 1, MPI_INT, parent, 0);

  // Phase 3: Wait from parent if not root
  if (rank != 0)
    mpi_recv(&msg, 1, MPI_INT, parent, 0);

  // Phase 4: Send to children
  if (left < size)
    mpi_send(&msg, 1, MPI_INT, left, 0);
  if (right < size)
    mpi_send(&msg, 1, MPI_INT, right, 0);

  return 0;
}

/* Enqueue `val` into queue `qid`. Returns 0 on success, -1 if full. */
static int queue_enqueue(__u32 qid, packet_info val) {
  __u32 head = 0, tail = 0;

  // Correctly lookup head and tail
  if (bpf_map_lookup_elem(EBPF_INFO.head_map_fd, &qid, &head) != 0) {
    // Initialize if not found
    head = 0;
    bpf_map_update_elem(EBPF_INFO.head_map_fd, &qid, &head, BPF_ANY);
  }

  if (bpf_map_lookup_elem(EBPF_INFO.tail_map_fd, &qid, &tail) != 0) {
    tail = 0;
    bpf_map_update_elem(EBPF_INFO.tail_map_fd, &qid, &tail, BPF_ANY);
  }

  __u32 next_tail = (tail + 1) & QUEUE_MASK;
  if (next_tail == (head & QUEUE_MASK)) {
    return -1; // Queue full
  }

  __u32 flat = qid * QUEUE_SIZE + (tail & QUEUE_MASK);
  if (bpf_map_update_elem(EBPF_INFO.queue_map_fd, &flat, &val, BPF_ANY) != 0) {
    return -1;
  }

  tail++;
  bpf_map_update_elem(EBPF_INFO.tail_map_fd, &qid, &tail, BPF_ANY);
  return 0;
}

/* Dequeue from queue `qid` into `*out`. Returns 0 on success, -1 if empty. */
static int queue_dequeue(__u32 qid, packet_info *out) {
  __u32 head = 0, tail = 0;

  if (bpf_map_lookup_elem(EBPF_INFO.head_map_fd, &qid, &head) != 0) {
    return -1; // Queue doesn't exist
  }

  if (bpf_map_lookup_elem(EBPF_INFO.tail_map_fd, &qid, &tail) != 0) {
    return -1; // Queue doesn't exist
  }

  if ((head & QUEUE_MASK) == (tail & QUEUE_MASK)) {
    return -1; // Queue empty
  }

  __u32 flat = qid * QUEUE_SIZE + (head & QUEUE_MASK);
  if (bpf_map_lookup_elem(EBPF_INFO.queue_map_fd, &flat, out) != 0) {
    return -1;
  }

  head++;
  bpf_map_update_elem(EBPF_INFO.head_map_fd, &qid, &head, BPF_ANY);
  return 0;
}

int mpi_send_xdp(const void *buf, int count, MPI_Datatype datatype, int dest,
                 int tag, packet_info *value) {

  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    return -1;
  }

  // Create message with tag header (same as regular mpi_send)
  int payload_size = sizeof(int) + size;
  void *message = malloc(payload_size);
  if (!message) {
    perror("malloc failed");
    return -1;
  }

  // Add tag to message header
  void *tag_send = message;
  generic_hton(tag_send, &tag, sizeof(int), 1);

  // Add data payload (same conversion logic as mpi_send)
  void *buf_send = (char *)message + sizeof(int);
  switch (datatype) {
  case MPI_CHAR:
    generic_hton(buf_send, buf, sizeof(char), count);
    break;
  case MPI_SIGNED_CHAR:
    generic_hton(buf_send, buf, sizeof(signed char), count);
    break;
  case MPI_UNSIGNED_CHAR:
    generic_hton(buf_send, buf, sizeof(unsigned char), count);
    break;
  case MPI_SHORT:
    generic_hton(buf_send, buf, sizeof(short), count);
    break;
  case MPI_UNSIGNED_SHORT:
    generic_hton(buf_send, buf, sizeof(unsigned short), count);
    break;
  case MPI_INT:
    generic_hton(buf_send, buf, sizeof(int), count);
    break;
  case MPI_UNSIGNED:
    generic_hton(buf_send, buf, sizeof(unsigned), count);
    break;
  case MPI_LONG:
    generic_hton(buf_send, buf, sizeof(long), count);
    break;
  case MPI_UNSIGNED_LONG:
    generic_hton(buf_send, buf, sizeof(unsigned long), count);
    break;
  case MPI_LONG_LONG:
    generic_hton(buf_send, buf, sizeof(long long), count);
    break;
  case MPI_UNSIGNED_LONG_LONG:
    generic_hton(buf_send, buf, sizeof(unsigned long long), count);
    break;
  case MPI_FLOAT:
    generic_hton(buf_send, buf, sizeof(float), count);
    break;
  case MPI_DOUBLE:
    generic_hton(buf_send, buf, sizeof(double), count);
    break;
  case MPI_LONG_DOUBLE:
    generic_hton(buf_send, buf, sizeof(long double), count);
    break;
  case MPI_C_BOOL:
    generic_hton(buf_send, buf, sizeof(bool), count);
    break;
  case MPI_WCHAR:
    generic_hton(buf_send, buf, sizeof(wchar_t), count);
    break;
  default:
    free(message);
    return -1;
  }

  // Get socket info for the destination process
  tuple_process key = {MPI_PROCESS->rank, dest};
  socket_id socket_info = {0};

  if (bpf_map_lookup_elem(EBPF_INFO.mpi_send_map_fd, &key, &socket_info) != 0) {
    printf("Failed to lookup socket info for rank %d -> %d\n",
           MPI_PROCESS->rank, dest);
    free(message);
    return -1;
  }

  // Extract MAC addresses from the packet_info value parameter
  // Assuming you want to swap source and destination MAC addresses
  uint8_t dst_mac[ETH_ALEN];
  uint8_t src_mac[ETH_ALEN];

  // Extract MAC addresses from ethernet header in packet_info
  // Copy source MAC from packet_info as destination MAC for our packet
  memcpy(dst_mac, &value->eth_hdr[6],
         ETH_ALEN); // Source MAC from received packet
  // memcpy(dst_mac, 0xFF,
  //        ETH_ALEN); // Source MAC from received packet
  // // Copy destination MAC from packet_info as source MAC for our packet
  memcpy(src_mac, &value->eth_hdr[0],
         ETH_ALEN); // Dest MAC from received packet
  // memcpy(src_mac, 0x00,
  //        ETH_ALEN); // Dest MAC from received packet

  // Build the complete packet
  size_t eth_hdr_len = sizeof(struct ether_header);
  size_t ip_hdr_len = sizeof(struct iphdr);
  size_t udp_hdr_len = sizeof(struct udphdr);
  size_t total_len = eth_hdr_len + ip_hdr_len + udp_hdr_len + payload_size;

  uint8_t *packet = malloc(total_len);
  if (!packet) {
    free(message);
    return -1;
  }
  memset(packet, 0, total_len);

  // 1) Ethernet header
  struct ether_header *eth = (struct ether_header *)packet;
  memcpy(eth->ether_dhost, dst_mac, ETH_ALEN); // Use extracted dest MAC
  memcpy(eth->ether_shost, src_mac, ETH_ALEN); // Use extracted source MAC
  eth->ether_type = htons(ETHERTYPE_IP);

  // 2) IPv4 header
  struct iphdr *ip = (struct iphdr *)(packet + eth_hdr_len);
  ip->version = 4;
  ip->ihl = ip_hdr_len / 4; // 5 words = 20 bytes
  ip->tos = 0;
  ip->tot_len = htons(ip_hdr_len + udp_hdr_len + payload_size);
  ip->id = htons(0x1234);
  ip->frag_off = htons(0x4000); // DF set
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = socket_info.src_ip; // Use socket info from BPF map
  ip->daddr = socket_info.dst_ip; // Use socket info from BPF map
  ip->check = 0;
  ip->check = ip_checksum(ip, ip_hdr_len);

  // 3) UDP header
  struct udphdr *udp = (struct udphdr *)(packet + eth_hdr_len + ip_hdr_len);
  udp->source = htons(socket_info.src_port);
  udp->dest = htons(socket_info.dst_port);
  udp->len = htons(udp_hdr_len + payload_size);
  udp->check = 0; // UDP checksum is optional for IPv4

  // 4) Copy MPI payload (tag + data)
  memcpy(packet + eth_hdr_len + ip_hdr_len + udp_hdr_len, message,
         payload_size);

  // Now test the packet through XDP program
  struct bpf_test_run_opts opts = {0};
  opts.sz = sizeof(opts);
  opts.flags = BPF_F_TEST_XDP_LIVE_FRAMES; // Don't use live frames for
  // testing
  // opts.flags = 0; // Don't use live frames for testing
  opts.repeat = 0;
  opts.duration = 0;
  opts.cpu = 0;
  opts.batch_size = 1;

  // Provide the constructed packet as input
  opts.data_in = packet;
  opts.data_size_in = total_len;

  // Buffer for output (XDP might modify the packet)
  // uint8_t data_out[2048];
  opts.data_out = NULL;
  opts.data_size_out = 0;

  // No context needed for this test
  opts.ctx_in = NULL;
  opts.ctx_out = NULL;
  opts.ctx_size_in = 0;
  opts.ctx_size_out = 0;
  // DECLARE_LIBBPF_OPTS(
  //     bpf_test_run_opts, opts, .data_in = packet, .data_size_in = total_len,
  //     .ctx_in = NULL, .ctx_size_in = 0, .repeat = 1,
  //     .flags = BPF_F_TEST_XDP_LIVE_FRAMES, .batch_size = 1, .cpu = 0);

  printf("Testing XDP program with constructed packet (rank %d -> %d)...\n",
         MPI_PROCESS->rank, dest);

  int ret = bpf_prog_test_run_opts(EBPF_INFO.loader->prog_fd, &opts);
  printf("bpf out: %d\n", opts.retval);
  // int ret =
  //     xdp_program__test_run(EBPF_INFO.loader->prog, &opts,
  //     BPF_PROG_TEST_RUN);

  if (ret < 0) {
    fprintf(stderr, "bpf_prog_test_run_opts failed: %s\n", strerror(-ret));
    free(message);
    free(packet);
    return -1;
  }

  printf("XDP program returned: %d, duration: %u ns\n", ret, opts.duration);

  // Optionally, you could also send the packet via normal UDP socket
  // as a fallback or for verification
  // ssize_t sent =
  //     sendto(udp_socket_fd, message, payload_size, 0,
  //            (struct sockaddr *)&peer_addrs[dest], sizeof(struct
  //            sockaddr_in));

  // if (sent != payload_size) {
  //   perror("sendto failed");
  //   free(message);
  //   free(packet);
  //   return -1;
  // }

  free(message);
  free(packet);
  return count;
}

int mpi_bcast(void *buf, int count, MPI_Datatype datatype, int root) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;
  packet_info recv_packet_info = {0};

  // Transform rank to [0..size) with root→0
  int rel = (rank - root + size) % size;
  // int max_rounds = (int)log2(size);

  printf("Process %d starting broadcast (root=%d, rel=%d)\n", rank, root, rel);

  // log₂(size) rounds
  for (int step = 1, round = 0; step < size; step <<= 1, ++round) {
    int tag = 1; // unique tag for this round

    if (rel < step) {
      // Sender phase
      int dst = rel + step;
      if (dst < size) {
        int real_dst = (dst + root) % size;
        printf("Process %d sending to %d (round %d)\n", rank, real_dst, round);

        if (rank == root) {
          // Root uses regular UDP send
          mpi_send(buf, count, datatype, real_dst, tag);
        } else {
          // Non-root processes use XDP-aware send
          // First, get packet info from previous receive
          printf("MY RANK :%d\n", MPI_PROCESS->rank);
          mpi_send_xdp(buf, count, datatype, real_dst, 2, &recv_packet_info);
        }
      }
    } else if (rel < step * 2) {
      // Receiver phase
      int src = rel - step;
      if (src >= 0) {
        int real_src = (src + root) % size;
        printf("Process %d receiving from %d (round %d)\n", rank, real_src,
               round);

        // Receive the actual MPI data
        int err = mpi_recv(buf, count, datatype, real_src, tag);
        if (err < 0) {
          printf("Error receiving from process %d\n", real_src);
          return -1;
        }

        // Try to get corresponding packet metadata from eBPF queue
        int queue_result = queue_dequeue(rank, &recv_packet_info);
        if (queue_result == 0) {
          printf("Process %d: Got packet metadata from eBPF:\n", rank);
          printf("  - Interface: %u\n", recv_packet_info.ingress_ifindex);
          printf("  - Total length: %u bytes\n", recv_packet_info.total_len);
          printf("  - Ethernet header: ");
          for (int i = 0; i < 6; i++) {
            printf("%02x:", recv_packet_info.eth_hdr[i]);
          }
          printf(" -> ");
          for (int i = 6; i < 12; i++) {
            printf("%02x:", recv_packet_info.eth_hdr[i]);
          }
          printf("\n");

          // Extract IP header info
          struct iphdr *ip = (struct iphdr *)recv_packet_info.ip_hdr;
          struct in_addr src_addr = {.s_addr = ip->saddr};
          struct in_addr dst_addr = {.s_addr = ip->daddr};
          printf("  - IP: %s -> %s\n", inet_ntoa(src_addr),
                 inet_ntoa(dst_addr));

          // Extract UDP header info
          struct udphdr *udp = (struct udphdr *)recv_packet_info.udp_hdr;
          printf("  - UDP: %u -> %u\n", ntohs(udp->source), ntohs(udp->dest));
        } else {
          printf("Process %d: No packet metadata available in eBPF queue\n",
                 rank);
        }
      }
    }
  }

  printf("Process %d completed broadcast\n", rank);
  return 0;
}

int mpi_bcast_ring(void *buf, int count, MPI_Datatype datatype, int root) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;
  int tag = 1; // you can choose any tag
  int next = (rank + 1) % size;
  int prev = (rank - 1 + size) % size;
  int pred_root = (root - 1 + size) % size;
  packet_info recv_info = {0};

  // 1) Root kicks off by sending to (root+1)%size
  if (rank == root) {
    printf("Process %d (root) sending to %d\n", rank, next);
    mpi_send(buf, count, datatype, next, tag);
  }

  // 2) Everyone except root must receive from their predecessor
  if (rank != root) {
    printf("Process %d receiving from %d\n", rank, prev);
    if (mpi_recv(buf, count, datatype, prev, tag) < 0) {
      fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
      return -1;
    }

    // (Optional) pull off XDP metadata if you’re using that path:
    if (queue_dequeue(rank, &recv_info) == 0) {
      // … inspect recv_info …
    }
  }

  // 3) And everyone except the predecessor of root forwards to their “next”
  //    This stops the packet from looping back to root.
  if (rank != pred_root) {
    printf("Process %d forwarding to %d\n", rank, next);
    if (rank == root) {
      // root already used mpi_send above;
      // if you want XDP‐send for everyone, swap these two calls
    } else {
      mpi_send_xdp(buf, count, datatype, next, 2, &recv_info);
      // mpi_send(buf, count, datatype, next, 2);
    }
  }

  return 0;
}