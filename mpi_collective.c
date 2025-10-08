#define _GNU_SOURCE
#include "mpi_collective.h"
size_t WORD_SIZE = 1;
MPI_process_info *MPI_PROCESS = NULL;
// Global peer address table
struct sockaddr_in *peer_addrs = NULL;
int udp_socket_fd = -1;
int udp_socket_barrier_fd = -1;

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
  inet_pton(AF_INET, "192.168.101.2", &id->dst_ip);
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
  tv_out.tv_sec = 10;
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
  // addr.sin_addr.s_addr = inet_addr("192.168.101.2");

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
  udp_socket_barrier_fd = create_udp_socket(BARRIER_PORT + rank);

  // Store the single UDP socket - maintaining compatibility with existing
  // structure
  mpi_process_info->socket_fd = (int *)malloc(WORD_SIZE * sizeof(int));
  if (mpi_process_info->socket_fd == NULL) {
    perror("malloc skoket_fd fail\n");
    exit(EXIT_FAILURE);
  }
  memset(mpi_process_info->socket_fd, -1, WORD_SIZE * sizeof(int));
  mpi_process_info->socket_fd[0] = udp_socket_fd; // Store UDP socket at index 0
  mpi_process_info->socket_barrier_fd = (int *)malloc(WORD_SIZE * sizeof(int));
  if (mpi_process_info->socket_barrier_fd == NULL) {
    perror("malloc skoket_fd fail\n");
    exit(EXIT_FAILURE);
  }
  memset(mpi_process_info->socket_barrier_fd, -1, WORD_SIZE * sizeof(int));
  mpi_process_info->socket_barrier_fd[0] =
      udp_socket_barrier_fd; // Store UDP socket at index 0

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
    inet_pton(AF_INET, GRECALE_IP, &peer_addrs[i].sin_addr);
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
      out_socket_map.src_ip = inet_addr(MAESTRALE_IP);
      out_socket_map.dst_ip = inet_addr(GRECALE_IP);
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
      in_socket_map.src_ip = inet_addr(MAESTRALE_IP);
      in_socket_map.dst_ip = inet_addr(GRECALE_IP);
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
      out_socket_map.src_ip = inet_addr(MAESTRALE_IP);
      out_socket_map.dst_ip = inet_addr(GRECALE_IP);
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
      in_socket_map.src_ip = inet_addr(MAESTRALE_IP);
      in_socket_map.dst_ip = inet_addr(GRECALE_IP);
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

int bytes_size_in_unit(int count, MPI_Datatype datatype) {
  int res = -1;
  switch (datatype) {
  case MPI_CHAR:
    res = count / sizeof(char);
    break;
  case MPI_SIGNED_CHAR:
    res = count / sizeof(signed char);
    break;
  case MPI_UNSIGNED_CHAR:
    res = count / sizeof(unsigned char);
    break;
  case MPI_SHORT:
    res = count / sizeof(short);
    break;
  case MPI_UNSIGNED_SHORT:
    res = count / sizeof(unsigned short);
    break;
  case MPI_INT:
    res = count / sizeof(int);
    break;
  case MPI_UNSIGNED:
    res = count / sizeof(unsigned);
    break;
  case MPI_LONG:
    res = count / sizeof(long);
    break;
  case MPI_UNSIGNED_LONG:
    res = count / sizeof(unsigned long);
    break;
  case MPI_LONG_LONG:
    res = count / sizeof(long long);
    break;
  case MPI_UNSIGNED_LONG_LONG:
    res = count / sizeof(unsigned long long);
    break;
  case MPI_FLOAT:
    res = count / sizeof(float);
    break;
  case MPI_DOUBLE:
    res = count / sizeof(double);
    break;
  case MPI_LONG_DOUBLE:
    res = count / sizeof(long double);
    break;
  case MPI_C_BOOL:
    res = count / sizeof(bool);
    break;
  case MPI_WCHAR:
    res = count / sizeof(wchar_t);
    break;
  default:
    break;
  }
  return res;
}

static int __mpi_send(const void *buf, int count, MPI_Datatype datatype,
                      int root, int dest, int tag, MPI_Collective collective) {
  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    return -1;
  }

  // Create message with tag header
  int total_size = (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                   (sizeof(int) * 2) + sizeof(unsigned long) + size;
  // printf("send total size %d\n", total_size);

  unsigned long seq = 0;

  if (total_size > 1472) {
    size_t offset = 0;
    const size_t N = (size_t)ceil((double)total_size / (double)1472);
    size_t base = (size_t)ceil((double)size / (double)N);
    size_t base_and_head = (size_t)ceil((double)total_size / (double)N);
    size_t chunk = bytes_size_in_unit(base, datatype);
    size_t chunk_rem = bytes_size_in_unit(base + 1, datatype);
    size_t rem = total_size % N;
    // printf("send base: %lu chunk:%d chunk+:%d rem:%lu\n", base, chunk,
    //        chunk_rem, rem);
    for (size_t i = 0; i < rem; i++) {
      void *message = malloc(total_size);
      if (!message) {
        perror("malloc failed");
        return -1;
      }
      char header_mpi[4] = {'M', 'P', 'I', '\0'};
      void *header_mpi_send = message;
      generic_hton(header_mpi_send, header_mpi, sizeof(char), 4);
      // printf("%s\n", message);

      void *root_send = (char *)message + (sizeof(char) * 4);
      generic_hton(root_send, &root, sizeof(int), 1);

      void *src_send = (char *)message + (sizeof(char) * 4) + sizeof(int);
      generic_hton(src_send, &MPI_PROCESS->rank, sizeof(int), 1);

      void *dst_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 2);
      generic_hton(dst_send, &dest, sizeof(int), 1);

      void *opcode_send =
          (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3);
      generic_hton(opcode_send, &collective, sizeof(MPI_Collective), 1);

      void *datatype_send = (char *)message + (sizeof(char) * 4) +
                            (sizeof(int) * 3) + sizeof(MPI_Collective);
      generic_hton(datatype_send, &datatype, sizeof(MPI_Datatype), 1);

      void *len_send = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype);
      generic_hton(len_send, &chunk_rem, sizeof(int), 1);

      // Add tag to message header
      void *tag_send = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype) + sizeof(int);
      generic_hton(tag_send, &tag, sizeof(int), 1);
      // printf("%d\n", ntohl(*((int *)((char *)message + (sizeof(char) *
      // 4)))));
      void *seq_send = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype) + (sizeof(int) * 2);
      generic_hton(seq_send, &seq, sizeof(unsigned long), 1);

      // Add data payload
      void *buf_send = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype) + (sizeof(int) * 2) +
                       sizeof(unsigned long);

      void *bufptr = NULL;
      switch (datatype) {
      case MPI_CHAR:
        bufptr = (void *)((char *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(char), chunk_rem);
        // printf("rank: %d len: %d\n", MPI_PROCESS->rank, strlen(buf_send));
        break;
      case MPI_SIGNED_CHAR:
        bufptr = (void *)((signed char *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(signed char), chunk_rem);
        break;
      case MPI_UNSIGNED_CHAR:
        bufptr = (void *)((unsigned char *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(unsigned char), chunk_rem);
        break;
      case MPI_SHORT:
        bufptr = (void *)((short *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(short), chunk_rem);
        break;
      case MPI_UNSIGNED_SHORT:
        bufptr = (void *)((unsigned short *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(unsigned short), chunk_rem);
        break;
      case MPI_INT:
        bufptr = (void *)((int *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(int), chunk_rem);
        break;
      case MPI_UNSIGNED:
        bufptr = (void *)((unsigned *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(unsigned), chunk_rem);
        break;
      case MPI_LONG:
        bufptr = (void *)((long *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(long), chunk_rem);
        break;
      case MPI_UNSIGNED_LONG:
        bufptr = (void *)((unsigned long *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(unsigned long), chunk_rem);
        break;
      case MPI_LONG_LONG:
        bufptr = (void *)((long long *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(long long), chunk_rem);
        break;
      case MPI_UNSIGNED_LONG_LONG:
        bufptr = (void *)((unsigned long long *)buf + offset);
        generic_hton(buf_send, buf, sizeof(unsigned long long), chunk_rem);
        break;
      case MPI_FLOAT:
        bufptr = (void *)((float *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(float), chunk_rem);
        break;
      case MPI_DOUBLE:
        bufptr = (void *)((double *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(double), chunk_rem);
        break;
      case MPI_LONG_DOUBLE:
        bufptr = (void *)((long double *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(long double), chunk_rem);
        break;
      case MPI_C_BOOL:
        bufptr = (void *)((bool *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(bool), chunk_rem);
        break;
      case MPI_WCHAR:
        bufptr = (void *)((wchar_t *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(wchar_t), chunk_rem);
        break;
      default:
        free(message);
        return -1;
      }

      // Send UDP message using the global socket and peer address table
      ssize_t sent = sendto(udp_socket_fd, message, base + 1 + MPI_HEADER, 0,
                            (struct sockaddr *)&peer_addrs[dest],
                            sizeof(struct sockaddr_in));

      free(message);

      if (sent != (MPI_HEADER + base + 1)) {
        perror("sendto failed");
        return -1;
      }
      seq += 1;
      offset += chunk_rem;
    }
    for (size_t i = 0; i < (N - rem); i++) {
      void *message = malloc(total_size);
      if (!message) {
        perror("malloc failed");
        return -1;
      }
      char header_mpi[4] = {'M', 'P', 'I', '\0'};
      void *header_mpi_send = message;
      generic_hton(header_mpi_send, header_mpi, sizeof(char), 4);
      // printf("%s\n", message);

      void *root_send = (char *)message + (sizeof(char) * 4);
      generic_hton(root_send, &root, sizeof(int), 1);

      void *src_send = (char *)message + (sizeof(char) * 4) + sizeof(int);
      generic_hton(src_send, &MPI_PROCESS->rank, sizeof(int), 1);

      void *dst_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 2);
      generic_hton(dst_send, &dest, sizeof(int), 1);

      void *opcode_send =
          (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3);
      generic_hton(opcode_send, &collective, sizeof(MPI_Collective), 1);

      void *datatype_send = (char *)message + (sizeof(char) * 4) +
                            (sizeof(int) * 3) + sizeof(MPI_Collective);
      generic_hton(datatype_send, &datatype, sizeof(MPI_Datatype), 1);

      void *len_send = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype);
      generic_hton(len_send, &chunk, sizeof(int), 1);

      // Add tag to message header
      void *tag_send = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype) + sizeof(int);
      generic_hton(tag_send, &tag, sizeof(int), 1);
      // printf("%d\n", ntohl(*((int *)((char *)message + (sizeof(char) *
      // 4)))));
      void *seq_send = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype) + (sizeof(int) * 2);
      generic_hton(seq_send, &seq, sizeof(unsigned long), 1);

      // Add data payload
      void *buf_send = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype) + (sizeof(int) * 2) +
                       sizeof(unsigned long);

      void *bufptr = NULL;
      switch (datatype) {
      case MPI_CHAR: {
        bufptr = (void *)((char *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(char), chunk);
        // printf("rank: %d len: %d\n", MPI_PROCESS->rank, strlen(bufptr));
      } break;
      case MPI_SIGNED_CHAR: {
        bufptr = (void *)((signed char *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(signed char), chunk);
      } break;
      case MPI_UNSIGNED_CHAR: {
        bufptr = (void *)((unsigned char *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(unsigned char), chunk);
      } break;
      case MPI_SHORT: {
        bufptr = (void *)((short *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(short), chunk);
      } break;
      case MPI_UNSIGNED_SHORT: {
        bufptr = (void *)((unsigned short *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(unsigned short), chunk);
      } break;
      case MPI_INT: {
        bufptr = (void *)((int *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(int), chunk);
      } break;
      case MPI_UNSIGNED: {
        bufptr = (void *)((unsigned *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(unsigned), chunk);
      } break;
      case MPI_LONG: {
        bufptr = (void *)((long *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(long), chunk);
      } break;
      case MPI_UNSIGNED_LONG: {
        bufptr = (void *)((unsigned long *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(unsigned long), chunk);
      } break;
      case MPI_LONG_LONG: {
        bufptr = (void *)((long long *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(long long), chunk);
      } break;
      case MPI_UNSIGNED_LONG_LONG: {
        bufptr = (void *)((unsigned long long *)buf + offset);
        generic_hton(buf_send, buf, sizeof(unsigned long long), chunk);
      } break;
      case MPI_FLOAT: {
        bufptr = (void *)((float *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(float), chunk);
      } break;
      case MPI_DOUBLE: {
        bufptr = (void *)((double *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(double), chunk);
      } break;
      case MPI_LONG_DOUBLE: {
        bufptr = (void *)((long double *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(long double), chunk);
      } break;
      case MPI_C_BOOL: {
        bufptr = (void *)((bool *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(bool), chunk);
      } break;
      case MPI_WCHAR: {
        bufptr = (void *)((wchar_t *)buf + offset);
        generic_hton(buf_send, bufptr, sizeof(wchar_t), chunk);
      } break;
      default:
        free(message);
        return -1;
      }

      // Send UDP message using the global socket and peer address table
      ssize_t sent = sendto(udp_socket_fd, message, base + MPI_HEADER, 0,
                            (struct sockaddr *)&peer_addrs[dest],
                            sizeof(struct sockaddr_in));
      // printf("rank: %d send: %d\n", MPI_PROCESS->rank, sent);

      free(message);

      if (sent != (MPI_HEADER + base)) {
        perror("sendto failed");
        return -1;
      }
      seq += 1;
      offset += chunk;
    }
  } else {
    void *message = malloc(total_size);
    if (!message) {
      perror("malloc failed");
      return -1;
    }
    char header_mpi[4] = {'M', 'P', 'I', '\0'};
    void *header_mpi_send = message;
    generic_hton(header_mpi_send, header_mpi, sizeof(char), 4);
    // printf("%s\n", message);

    void *root_send = (char *)message + (sizeof(char) * 4);
    generic_hton(root_send, &root, sizeof(int), 1);

    void *src_send = (char *)message + (sizeof(char) * 4) + sizeof(int);
    generic_hton(src_send, &MPI_PROCESS->rank, sizeof(int), 1);

    void *dst_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 2);
    generic_hton(dst_send, &dest, sizeof(int), 1);

    void *opcode_send =
        (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3);
    generic_hton(opcode_send, &collective, sizeof(MPI_Collective), 1);

    void *datatype_send = (char *)message + (sizeof(char) * 4) +
                          (sizeof(int) * 3) + sizeof(MPI_Collective);
    generic_hton(datatype_send, &datatype, sizeof(MPI_Datatype), 1);

    void *len_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype);
    generic_hton(len_send, &count, sizeof(int), 1);

    // Add tag to message header
    void *tag_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     sizeof(int);
    generic_hton(tag_send, &tag, sizeof(int), 1);
    // printf("%d\n", ntohl(*((int *)((char *)message + (sizeof(char) *
    // 4)))));
    void *seq_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2);
    generic_hton(seq_send, &seq, sizeof(unsigned long), 1);

    // Add data payload
    void *buf_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2) + sizeof(unsigned long);
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
    ssize_t sent = sendto(udp_socket_fd, message, total_size, 0,
                          (struct sockaddr *)&peer_addrs[dest],
                          sizeof(struct sockaddr_in));

    free(message);

    if (sent != total_size) {
      perror("sendto failed");
      return -1;
    }
  }

  return count;
}

int mpi_send(const void *buf, int count, MPI_Datatype datatype, int dest,
             int tag) {

  return __mpi_send(buf, count, datatype, MPI_PROCESS->rank, dest, tag,
                    MPI_SEND);
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

  int total_size = (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                   (sizeof(int) * 2) + sizeof(unsigned long) + size;

  // printf("recv total size %d\n", total_size);
  if (total_size > 1472) {
    size_t offset = 0;
    const size_t N = ceil((double)total_size / (double)1472);
    size_t base = (size_t)ceil((double)size / (double)N);
    size_t base_rem = base + 1;
    size_t chunk = bytes_size_in_unit(base, datatype);
    size_t chunk_rem = bytes_size_in_unit(base + 1, datatype);
    size_t rem = total_size % N;
    unsigned long seqs[N];
    memset(seqs, 0, N);
    Array fragment[N];
    for (size_t i = 0; i < N; i++) {
      fragment[i].len = 0;
      fragment[i].arr = NULL;
    }
    // printf("recv base: %lu chunk:%d chunk+:%d rem:%lu\n", base, chunk,
    //        chunk_rem, rem);
    for (size_t i = 0; i < N; i++) {

      void *message = malloc(total_size);
      if (!message) {
        perror("malloc failed");
        return -1;
      }
      memset(message, 0, total_size);

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
      char header_mpi[4];
      generic_ntoh(header_mpi, message, sizeof(char), 4);

      int root;
      void *root_recv = (char *)message + (sizeof(char) * 4);
      generic_ntoh(&root, root_recv, sizeof(int), 1);

      int src;
      void *src_recv = (char *)message + (sizeof(char) * 4) + sizeof(int);
      generic_ntoh(&src, src_recv, sizeof(int), 1);

      int dst;
      void *dst_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 2);
      generic_ntoh(&dst, dst_recv, sizeof(int), 1);

      MPI_Collective collective;
      void *collective_recv =
          (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3);
      generic_ntoh(&collective, collective_recv, sizeof(MPI_Collective), 1);

      MPI_Datatype __datatype;
      void *datatype_recv = (char *)message + (sizeof(char) * 4) +
                            (sizeof(int) * 3) + sizeof(MPI_Collective);
      generic_ntoh(&__datatype, datatype_recv, sizeof(MPI_Datatype), 1);

      int len;
      void *len_recv = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype);
      generic_ntoh(&len, len_recv, sizeof(int), 1);

      // Add tag to message header
      // printf("%d\n", ntohl(*((int *)((char *)message + (sizeof(char) *
      // 4)))));

      int tag_int;
      void *tag_recv = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype) + sizeof(int);
      generic_ntoh(&tag, tag_recv, sizeof(int), 1);

      unsigned long seq;
      void *seq_recv = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype) + (sizeof(int) * 2);
      generic_ntoh(&seq, seq_recv, sizeof(unsigned long), 1);

      // Extract data payload
      void *buf_recv = (char *)message + (sizeof(char) * 4) +
                       (sizeof(int) * 3) + sizeof(MPI_Collective) +
                       sizeof(MPI_Datatype) + (sizeof(int) * 2) +
                       sizeof(unsigned long);
      int data_size =
          received -
          ((sizeof(char) * 4) + (sizeof(int) * 3) + sizeof(MPI_Collective) +
           sizeof(MPI_Datatype) + (sizeof(int) * 2) + sizeof(unsigned long));

      // printf("rank: %d datasize: %d, received: %d\n", MPI_PROCESS->rank,
      //        data_size, received);
      // size_t base_headless =
      //     base -
      //     ((sizeof(char) * 4) + (sizeof(int) * 3) + sizeof(MPI_Collective) +
      //      sizeof(MPI_Datatype) + (sizeof(int) * 2) + sizeof(unsigned long));
      // size_t base_rem_headless =
      //     (base_rem) -
      //     ((sizeof(char) * 4) + (sizeof(int) * 3) + sizeof(MPI_Collective) +
      //      sizeof(MPI_Datatype) + (sizeof(int) * 2) + sizeof(unsigned long));

      // if (data_size != base_headless && data_size != base_rem_headless) {
      //   free(message);
      //   printf("received data size mismatch:: 1\n");
      //   exit(EXIT_FAILURE);
      //   // }
      // }
      fragment[seq].len = len;
      fragment[seq].arr = malloc(datatype_size_in_bytes(len, datatype));
      switch (datatype) {
      case MPI_CHAR: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(char),
                     fragment[i].len);
        // printf("rank: %d, len: %d\n", MPI_PROCESS->rank, strlen(buf_recv));
        // char *buf_char = (char *)buf;
        // buf_char[count - 1] = '\0';
      } break;
      case MPI_SIGNED_CHAR: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(signed char),
                     fragment[i].len);
        // signed char *buf_char = (signed char *)buf;
        // buf_char[count - 1] = '\0';
      } break;
      case MPI_UNSIGNED_CHAR: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(unsigned char),
                     fragment[i].len);
        // unsigned char *buf_char = (unsigned char *)buf;
        // buf_char[count - 1] = '\0';
      } break;
      case MPI_SHORT: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(short),
                     fragment[i].len);
      } break;
      case MPI_UNSIGNED_SHORT: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(unsigned short),
                     fragment[i].len);
      } break;
      case MPI_INT: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(int), fragment[i].len);
      } break;
      case MPI_UNSIGNED: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(unsigned),
                     fragment[i].len);
      } break;
      case MPI_LONG: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(long),
                     fragment[i].len);
      } break;
      case MPI_UNSIGNED_LONG: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(unsigned long),
                     fragment[i].len);
      } break;
      case MPI_LONG_LONG: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(long long),
                     fragment[i].len);
      } break;
      case MPI_UNSIGNED_LONG_LONG: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(unsigned long long),
                     fragment[i].len);
      } break;
      case MPI_FLOAT: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(float),
                     fragment[i].len);
      } break;
      case MPI_DOUBLE: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(double),
                     fragment[i].len);
      } break;
      case MPI_LONG_DOUBLE: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(long double),
                     fragment[i].len);
      } break;
      case MPI_C_BOOL: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(bool),
                     fragment[i].len);
      } break;
      case MPI_WCHAR: {
        generic_ntoh(fragment[seq].arr, buf_recv, sizeof(wchar_t),
                     fragment[i].len);
        // wchar_t *buf_char = (wchar_t *)buf;
        // buf_char[count - 1] = L'\0';
      } break;
      default:
        free(message);
        return -1;
      }

      free(message);
    }
    for (size_t i = 0; i < N; i++) {

      void *bufptr = NULL;
      switch (datatype) {
      case MPI_CHAR: {
        bufptr = (void *)((char *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(char), fragment[i].len);
        // memcpy(bufptr, fragment[i].arr, fragment[i].len);
        char *buf_char = (char *)buf;
        buf_char[count - 1] = '\0';
        // printf("rank: %d 0\n%s\n", MPI_PROCESS->rank, (char *)bufptr);
        // printf("1. rank: %d  char: %s seq: %lu buf: %p bufptr: %p len: %lu "
        //        "offset: %d len__: %d\n",
        //        MPI_PROCESS->rank, ((char *)fragment[i].arr), i, buf, bufptr,
        //        fragment[i].len, offset, strlen(fragment[i].arr));
        // print_mpi_message(buf_recv, chunk, MPI_CHAR);
      } break;
      case MPI_SIGNED_CHAR: {
        bufptr = (void *)((signed char *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(signed char),
                     fragment[i].len);
        signed char *buf_char = (signed char *)bufptr;
        buf_char[count - 1] = '\0';
      } break;
      case MPI_UNSIGNED_CHAR: {
        bufptr = (void *)((unsigned char *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(unsigned char),
                     fragment[i].len);
        unsigned char *buf_char = (unsigned char *)bufptr;
        buf_char[count - 1] = '\0';
      } break;
      case MPI_SHORT: {
        bufptr = (void *)((short *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(short), fragment[i].len);
      } break;
      case MPI_UNSIGNED_SHORT: {
        bufptr = (void *)((unsigned short *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(unsigned short),
                     fragment[i].len);
      } break;
      case MPI_INT: {
        bufptr = (void *)((int *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(int), fragment[i].len);
      } break;
      case MPI_UNSIGNED: {
        bufptr = (void *)((unsigned *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(unsigned),
                     fragment[i].len);
      } break;
      case MPI_LONG: {
        bufptr = (void *)((long *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(long), fragment[i].len);
      } break;
      case MPI_UNSIGNED_LONG: {
        bufptr = (void *)((unsigned long *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(unsigned long),
                     fragment[i].len);
      } break;
      case MPI_LONG_LONG: {
        bufptr = (void *)((long long *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(long long),
                     fragment[i].len);
      } break;
      case MPI_UNSIGNED_LONG_LONG: {
        bufptr = (void *)((unsigned long long *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(unsigned long long),
                     fragment[i].len);
      } break;
      case MPI_FLOAT: {
        bufptr = (void *)((float *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(float), fragment[i].len);
      } break;
      case MPI_DOUBLE: {
        bufptr = (void *)((double *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(double), fragment[i].len);
      } break;
      case MPI_LONG_DOUBLE: {
        bufptr = (void *)((long double *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(long double),
                     fragment[i].len);
      } break;
      case MPI_C_BOOL: {
        bufptr = (void *)((bool *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(bool), fragment[i].len);
      } break;
      case MPI_WCHAR: {
        bufptr = (void *)((wchar_t *)buf + offset);
        generic_ntoh(bufptr, fragment[i].arr, sizeof(wchar_t), fragment[i].len);
        wchar_t *buf_char = (wchar_t *)bufptr;
        buf_char[count - 1] = L'\0';
      } break;
      default:
        return -1;
      }

      offset += fragment[i].len;
    }
    for (size_t i = 0; i < N; i++) {
      free(fragment[i].arr);
    }
  } else {
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
    char header_mpi[4];
    generic_ntoh(header_mpi, message, sizeof(char), 4);

    int root;
    void *root_recv = (char *)message + (sizeof(char) * 4);
    generic_ntoh(&root, root_recv, sizeof(int), 1);

    int src;
    void *src_recv = (char *)message + (sizeof(char) * 4) + sizeof(int);
    generic_ntoh(&src, src_recv, sizeof(int), 1);

    // if (root != source) {
    //   perror("root differet from the source\n");
    //   exit(EXIT_FAILURE);
    // }

    int dst;
    void *dst_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 2);
    generic_ntoh(&dst, dst_recv, sizeof(int), 1);

    MPI_Collective collective;
    void *collective_recv =
        (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3);
    generic_ntoh(&collective, collective_recv, sizeof(MPI_Collective), 1);

    MPI_Datatype __datatype;
    void *datatype_recv = (char *)message + (sizeof(char) * 4) +
                          (sizeof(int) * 3) + sizeof(MPI_Collective);
    generic_ntoh(&__datatype, datatype_recv, sizeof(MPI_Datatype), 1);

    int len;
    void *len_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype);
    generic_ntoh(&len, len_recv, sizeof(int), 1);

    // Add tag to message header
    // printf("%d\n", ntohl(*((int *)((char *)message + (sizeof(char) *
    // 4)))));

    int tag_int;
    void *tag_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     sizeof(int);
    generic_ntoh(&tag, tag_recv, sizeof(int), 1);

    unsigned long seq;
    void *seq_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2);
    generic_ntoh(&seq, &seq_recv, sizeof(unsigned long), 1);

    // Extract data payload
    void *buf_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                     sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                     (sizeof(int) * 2) + sizeof(unsigned long);
    int data_size = received - ((sizeof(char) * 4) + (sizeof(int) * 3) +
                                sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                                (sizeof(int) * 2) + sizeof(unsigned long));

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
      buf_char[count - 1] = '\0';
    } break;
    case MPI_SIGNED_CHAR: {
      generic_ntoh(buf, buf_recv, sizeof(signed char), count);
      signed char *buf_char = (signed char *)buf;
      buf_char[count - 1] = '\0';
    } break;
    case MPI_UNSIGNED_CHAR: {
      generic_ntoh(buf, buf_recv, sizeof(unsigned char), count);
      unsigned char *buf_char = (unsigned char *)buf;
      buf_char[count - 1] = '\0';
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
      buf_char[count - 1] = L'\0';
    } break;
    default:
      free(message);
      return -1;
    }

    free(message);
  }
  return count;
}

// int mpi_barrier(void) {
//   char bit[1] = "0";
//   mpi_bcast_ring(bit, sizeof(bit) / sizeof(char), MPI_CHAR, 0);
//   return 0;
// }

int mpi_barrier(void) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;
  int msg = 1;

  int parent = (rank - 1) / 2;
  int left = 2 * rank + 1;
  int right = 2 * rank + 2;

  // Phase 1: Wait for messages from children
  if (left < size)
    mpi_recv(&msg, 1, MPI_INT, left, -1);
  if (right < size)
    mpi_recv(&msg, 1, MPI_INT, right, -1);

  // Phase 2: Notify parent
  if (rank != 0)
    mpi_send(&msg, 1, MPI_INT, parent, -1);

  // Phase 3: Wait from parent if not root
  if (rank != 0)
    mpi_recv(&msg, 1, MPI_INT, parent, -1);

  // Phase 4: Send to children
  if (left < size)
    mpi_send(&msg, 1, MPI_INT, left, -1);
  if (right < size)
    mpi_send(&msg, 1, MPI_INT, right, -1);
  usleep(100000); // 100ms delay
  // sleep(1); // 100ms delay

  return 0;
}

int mpi_barrier_ring(void) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;
  int dummy = 0;
  int tag = -1; // Use a unique tag far from your other operations

  // Simple ring-based barrier (compatible with your broadcast)
  int next = (rank + 1) % size;
  int prev = (rank - 1 + size) % size;

  // sleep(1);
  if (rank == 0) {
    // Root: send to next, then receive from prev
    mpi_send(&dummy, 1, MPI_INT, next, tag);
    mpi_recv(&dummy, 1, MPI_INT, prev, tag);
  } else {
    // Others: receive from prev, then send to next
    mpi_recv(&dummy, 1, MPI_INT, prev, tag);
    mpi_send(&dummy, 1, MPI_INT, next, tag);
  }

  return 0;
}

int mpi_bcast(void *buf, int count, MPI_Datatype datatype, int root) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;

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
          // mpi_send_xdp(buf, count, datatype, real_dst, tag,
          // &recv_packet_info);
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

  // 1) Root kicks off by sending to (root+1)%size
  if (rank == root) {
    // printf("Process %d (root) sending to %d\n", rank, next);
    mpi_send(buf, count, datatype, next, tag);
  }

  // 2) Everyone except root must receive from their predecessor
  if (rank != root) {
    // printf("Process %d receiving from %d\n", rank, prev);
    if (mpi_recv(buf, count, datatype, prev, tag) < 0) {
      fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
      return -1;
    }
  }

  // 3) And everyone except the predecessor of root forwards to their “next”
  //  This stops the packet from looping back to root.
  if (rank != pred_root) {
    // printf("Process %d forwarding to %d\n", rank, next);
    if (rank == root) {
      // root already used mpi_send above;
      // if you want XDP‐send for everyone, swap these two calls
    } else {
      // mpi_send_xdp(buf, count, datatype, next, tag, &recv_info);
      mpi_send(buf, count, datatype, next, tag);
    }
  }

  return 0;
}

int mpi_bcast_ring_xdp(void *buf, int count, MPI_Datatype datatype, int root) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;
  int tag = 1; // you can choose any tag
  int next = (rank + 1) % size;
  int prev = (rank - 1 + size) % size;
  int pred_root = (root - 1 + size) % size;

  // 1) Root kicks off by sending to (root+1)%size
  if (rank == root) {
    // printf("Process %d (root) sending to %d\n", rank, next);
    __mpi_send(buf, count, datatype, root, next, tag, MPI_BCAST);
  }

  // 2) Everyone except root must receive from their predecessor
  if (rank != root) {
    // printf("Process %d receiving from %d\n", rank, prev);
    if (mpi_recv(buf, count, datatype, prev, tag) < 0) {
      fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
      return -1;
    }
  }

  return 0;
}

int mpi_opcode(void *buf, void *buf_local, size_t len, MPI_Datatype datatype,
               MPI_Opcode opcode) {
  switch (datatype) {
  case MPI_CHAR: {
    char *__buf = (char *)buf;
    char *__buf_local = (char *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_SIGNED_CHAR: {
    signed char *__buf = (signed char *)buf;
    signed char *__buf_local = (signed char *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_UNSIGNED_CHAR: {
    unsigned char *__buf = (unsigned char *)buf;
    unsigned char *__buf_local = (unsigned char *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_SHORT: {
    short *__buf = (short *)buf;
    short *__buf_local = (short *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_UNSIGNED_SHORT: {
    unsigned short *__buf = (unsigned short *)buf;
    unsigned short *__buf_local = (unsigned short *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_INT: {
    int *__buf = (int *)buf;
    int *__buf_local = (int *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_UNSIGNED: {
    unsigned *__buf = (unsigned *)buf;
    unsigned *__buf_local = (unsigned *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_LONG: {
    long *__buf = (long *)buf;
    long *__buf_local = (long *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_UNSIGNED_LONG: {
    unsigned long *__buf = (unsigned long *)buf;
    unsigned long *__buf_local = (unsigned long *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_LONG_LONG: {
    long long *__buf = (long long *)buf;
    long long *__buf_local = (long long *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_UNSIGNED_LONG_LONG: {
    unsigned long long *__buf = (unsigned long long *)buf;
    unsigned long long *__buf_local = (unsigned long long *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_FLOAT: {
    float *__buf = (float *)buf;
    float *__buf_local = (float *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_DOUBLE: {
    double *__buf = (double *)buf;
    double *__buf_local = (double *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_LONG_DOUBLE: {
    long double *__buf = (long double *)buf;
    long double *__buf_local = (long double *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_C_BOOL: {
    bool *__buf = (bool *)buf;
    bool *__buf_local = (bool *)buf_local;
    switch (opcode) {
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  case MPI_WCHAR: {
    wchar_t *__buf = (wchar_t *)buf;
    wchar_t *__buf_local = (wchar_t *)buf_local;
    switch (opcode) {
    case MPI_SUM: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] += __buf_local[i];
      }
    } break;
    case MPI_PROD: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] *= __buf_local[i];
      }
    } break;
    case MPI_MAX: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] > __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_MIN: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf_local[i] < __buf[i] ? __buf_local[i] : __buf[i];
      }
    } break;
    case MPI_LAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] && __buf_local[i];
      }
    } break;
    case MPI_LOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] || __buf_local[i];
      }
    } break;
    case MPI_LXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] != __buf_local[i];
      }
    } break;
    case MPI_BAND: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] & __buf_local[i];
      }
    } break;
    case MPI_BOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] | __buf_local[i];
      }
    } break;
    case MPI_BXOR: {
      for (size_t i = 0; i < len; i++) {
        __buf[i] = __buf[i] ^ __buf_local[i];
      }
    } break;
    default:
      perror("unsuport operation with this tipe");
      exit(EXIT_FAILURE);
      break;
    }
  } break;
  default:
    return -1;
  }
  return 0;
}

int mpi_reduce_ring(void *buf, int count, MPI_Datatype datatype,
                    MPI_Opcode opcode, int root) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;
  int tag = 1; // you can choose any tag
  int next = (rank + 1) % size;
  int prev = (rank - 1 + size) % size;
  // int pred_root = (root - 1 + size) % size;

  // 1) Root kicks off by sending to (root+1)%size
  if (rank != root) {
    // printf("Process %d receiving from %d\n", rank, prev);
    __mpi_send(buf, count, datatype, root, root, tag, MPI_REDUCE);
  }

  // 2) Everyone except root must receive from their predecessor
  if (rank == root) {
    for (size_t i = 0; i < size - 1; i++) {
      // printf("Process %d (root) sending to %d\n", rank, root);
      switch (datatype) {
      case MPI_CHAR: {
        char buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_SIGNED_CHAR: {
        signed char buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_UNSIGNED_CHAR: {
        unsigned char buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_SHORT: {
        short buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_UNSIGNED_SHORT: {
        unsigned short buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_INT: {
        int buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_UNSIGNED: {
        unsigned buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_LONG: {
        long buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_UNSIGNED_LONG: {
        unsigned long buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_LONG_LONG: {
        long long buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_UNSIGNED_LONG_LONG: {
        unsigned long long buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_FLOAT: {
        float buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_DOUBLE: {
        double buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_LONG_DOUBLE: {
        long double buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_C_BOOL: {
        bool buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      case MPI_WCHAR: {
        wchar_t buf_local[count];
        if (mpi_recv(buf_local, count, datatype, MPI_ANY_SOURCE, tag) < 0) {
          fprintf(stderr, "Process %d: recv from %d failed\n", rank, prev);
          return -1;
        }
        if (mpi_opcode(buf, buf_local, count, datatype, opcode) != 0) {
          perror("error mpi_opcode\n");
          exit(EXIT_FAILURE);
        }
      } break;
      default:
        return -1;
      }
    }
  }

  return 0;
}
