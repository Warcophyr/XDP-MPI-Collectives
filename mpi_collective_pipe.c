#define _GNU_SOURCE
#include "mpi_collective.h"

size_t WORD_SIZE = 1;
MPI_process_info *MPI_PROCESS = NULL;
struct sockaddr_in *peer_addrs = NULL;
int udp_socket_fd = -1;
struct sockaddr_in *ack_peer_addrs = NULL;
int ack_socket_fd = -1;

// Global pipe arrays for inter-process communication
static int **pipe_fds_send =
    NULL; // pipe_fds_send[rank] - pipes for sending TO rank
static int **pipe_fds_recv =
    NULL; // pipe_fds_recv[rank] - pipes for receiving FROM rank

int extract_5tuple(int sockfd, struct socket_id *id) {
  struct sockaddr_in local_addr;
  socklen_t addr_len = sizeof(struct sockaddr_in);

  if (getsockname(sockfd, (struct sockaddr *)&local_addr, &addr_len) == -1) {
    perror("getsockname");
    return -1;
  }

  id->src_ip = local_addr.sin_addr.s_addr;
  id->src_port = ntohs(local_addr.sin_port);
  id->protocol = IPPROTO_UDP;

  inet_pton(AF_INET, "192.168.101.2", &id->dst_ip);
  id->dst_port = 0;

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

  if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind failed\n");
    exit(EXIT_FAILURE);
  }

  return socket_fd;
}

// Initialize pipes for all process pairs
int init_pipes(int rank) {
  // Allocate pipe arrays
  pipe_fds_send = (int **)malloc(WORD_SIZE * sizeof(int *));
  pipe_fds_recv = (int **)malloc(WORD_SIZE * sizeof(int *));

  if (!pipe_fds_send || !pipe_fds_recv) {
    perror("malloc pipe arrays failed");
    return -1;
  }

  for (int i = 0; i < WORD_SIZE; i++) {
    pipe_fds_send[i] = (int *)malloc(2 * sizeof(int));
    pipe_fds_recv[i] = (int *)malloc(2 * sizeof(int));

    if (!pipe_fds_send[i] || !pipe_fds_recv[i]) {
      perror("malloc pipe fd failed");
      return -1;
    }

    pipe_fds_send[i][0] = -1;
    pipe_fds_send[i][1] = -1;
    pipe_fds_recv[i][0] = -1;
    pipe_fds_recv[i][1] = -1;
  }

  return 0;
}

// Create pipes before forking - called from parent
int create_all_pipes() {
  for (int i = 0; i < WORD_SIZE; i++) {
    for (int j = 0; j < WORD_SIZE; j++) {
      if (i == j)
        continue;

      // Create pipe for i -> j communication
      int pipefd[2];
      if (pipe2(pipefd, O_NONBLOCK) == -1) {
        perror("pipe2 failed");
        return -1;
      }

      // Store pipe ends
      // Process i will write to pipefd[1], process j will read from pipefd[0]
      if (i < j) {
        pipe_fds_send[i][0] = pipefd[0]; // read end
        pipe_fds_send[i][1] = pipefd[1]; // write end
      } else {
        pipe_fds_recv[j][0] = pipefd[0]; // read end
        pipe_fds_recv[j][1] = pipefd[1]; // write end
      }
    }
  }
  return 0;
}

// Setup pipes for a specific rank after forking
int setup_rank_pipes(int rank) {
  for (int i = 0; i < WORD_SIZE; i++) {
    if (i == rank)
      continue;

    if (rank < i) {
      // Close unused ends
      if (pipe_fds_send[rank][0] != -1) {
        close(pipe_fds_send[rank][0]); // Close read end for sending
        pipe_fds_send[rank][0] = -1;
      }
      if (pipe_fds_recv[i][1] != -1) {
        close(pipe_fds_recv[i][1]); // Close write end for receiving
        pipe_fds_recv[i][1] = -1;
      }
    } else {
      // Close unused ends
      if (pipe_fds_recv[rank][1] != -1) {
        close(pipe_fds_recv[rank][1]); // Close write end for receiving
        pipe_fds_recv[rank][1] = -1;
      }
      if (pipe_fds_send[i][0] != -1) {
        close(pipe_fds_send[i][0]); // Close read end for sending
        pipe_fds_send[i][0] = -1;
      }
    }
  }
  return 0;
}

MPI_process_info *mpi_init(int rank, int mpi_sockets_map_fd,
                           int mpi_send_map_fd) {
  MPI_process_info *mpi_process_info =
      (MPI_process_info *)malloc(sizeof(MPI_process_info));
  if (mpi_process_info == NULL) {
    perror("malloc failed\n");
    exit(EXIT_FAILURE);
  }

  mpi_process_info->send_buff = malloc(MAX_PAYLOAD);
  mpi_process_info->recv_buff = malloc(MAX_PAYLOAD);
  mpi_process_info->ACK_buff = malloc(MPI_HEADER);
  mpi_process_info->rank = rank;

  mpi_process_info->ids =
      (unsigned long **)malloc(sizeof(unsigned long *) * WORD_SIZE);
  if (mpi_process_info->ids == NULL) {
    perror("malloc fail creating vector clock");
    exit(EXIT_FAILURE);
  }

  // Create UDP socket for this process
  udp_socket_fd = create_udp_socket(BASE_PORT + rank);

  mpi_process_info->socket_udp_fd = (int *)malloc(WORD_SIZE * sizeof(int));
  if (mpi_process_info->socket_udp_fd == NULL) {
    perror("malloc skoket_fd fail\n");
    exit(EXIT_FAILURE);
  }
  memset(mpi_process_info->socket_udp_fd, -1, WORD_SIZE * sizeof(int));
  mpi_process_info->socket_udp_fd[0] = udp_socket_fd;

  peer_addrs =
      (struct sockaddr_in *)malloc(WORD_SIZE * sizeof(struct sockaddr_in));

  for (int i = 0; i < WORD_SIZE; i++) {
    mpi_process_info->ids[i] =
        (unsigned long *)calloc(WORD_SIZE, sizeof(unsigned long));
    if (mpi_process_info->ids[i] == NULL) {
      perror("malloc fail creating vector clock");
      exit(EXIT_FAILURE);
    }
    if (i == rank) {
      memset(&peer_addrs[i], 0, sizeof(struct sockaddr_in));
      continue;
    }

    peer_addrs[i].sin_family = AF_INET;
    peer_addrs[i].sin_port = htons(BASE_PORT + i);
    inet_pton(AF_INET, GRECALE_IP, &peer_addrs[i].sin_addr);
  }

  ack_socket_fd = create_udp_socket(ACK_PORT + rank);
  ack_peer_addrs =
      (struct sockaddr_in *)malloc(WORD_SIZE * sizeof(struct sockaddr_in));

  for (int i = 0; i < WORD_SIZE; i++) {
    if (i == rank) {
      memset(&ack_peer_addrs[i], 0, sizeof(struct sockaddr_in));
      continue;
    }

    ack_peer_addrs[i].sin_family = AF_INET;
    ack_peer_addrs[i].sin_port = htons(ACK_PORT + i);
    inet_pton(AF_INET, "127.0.0.1", &ack_peer_addrs[i].sin_addr);
  }

  // Setup pipes for this rank
  setup_rank_pipes(rank);

  // Store pipe FDs in the socket_tcp_fd array (reusing the structure)
  mpi_process_info->socket_tcp_fd = (int *)malloc(WORD_SIZE * sizeof(int));
  memset(mpi_process_info->socket_tcp_fd, -1, WORD_SIZE * sizeof(int));

  for (int i = 0; i < WORD_SIZE; i++) {
    if (i == rank)
      continue;

    // Store the appropriate pipe FD for communication with rank i
    if (rank < i) {
      mpi_process_info->socket_tcp_fd[i] = pipe_fds_send[rank][1]; // Write end
    } else {
      mpi_process_info->socket_tcp_fd[i] = pipe_fds_recv[i][0]; // Read end
    }
  }

  sleep(1);

  // Update BPF maps
  if (mpi_sockets_map_fd >= 0) {
    for (int peer = 0; peer < WORD_SIZE; peer++) {
      if (peer == rank)
        continue;

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
    for (int peer = 0; peer < WORD_SIZE; peer++) {
      if (peer == rank)
        continue;

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
        printf("fail update map mpi_send_map for outgoing %d->%d\n", rank,
               peer);
      }

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
        printf("fail update map mpi_send_map for incoming %d->%d\n", peer,
               rank);
      }
    }
  }

  sleep(1);
  return mpi_process_info;
}

// Pipe send wrapper - writes all data
ssize_t pipe_send_all(int fd, const void *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t written = write(fd, (char *)buf + total, len - total);
    if (written < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        usleep(100); // Brief wait for pipe to be ready
        continue;
      }
      return -1;
    }
    total += written;
  }
  return total;
}

// Pipe recv wrapper - reads all data
ssize_t pipe_recv_all(int fd, void *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t nread = read(fd, (char *)buf + total, len - total);
    if (nread < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        usleep(100); // Brief wait for data
        continue;
      }
      return -1;
    }
    if (nread == 0) {
      break; // EOF
    }
    total += nread;
  }
  return total;
}

int __mpi_send_pipe(const void *buf, int count, MPI_Datatype datatype, int root,
                    int dest, int tag, MPI_Collective collective) {
  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    return -1;
  }

  int total_size = MPI_HEADER + size;
  void *message = malloc(total_size);
  if (!message) {
    perror("malloc failed");
    return -1;
  }

  char header_mpi[4] = {'M', 'P', 'I', '\0'};
  void *header_mpi_send = message;
  generic_hton(header_mpi_send, header_mpi, sizeof(char), 4);

  void *root_send = (char *)message + (sizeof(char) * 4);
  generic_hton(root_send, &root, sizeof(int), 1);

  void *src_send = (char *)message + (sizeof(char) * 4) + sizeof(int);
  generic_hton(src_send, &MPI_PROCESS->rank, sizeof(int), 1);

  void *dst_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 2);
  generic_hton(dst_send, &dest, sizeof(int), 1);

  void *opcode_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3);
  generic_hton(opcode_send, &collective, sizeof(MPI_Collective), 1);

  void *datatype_send = (char *)message + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective);
  generic_hton(datatype_send, &datatype, sizeof(MPI_Datatype), 1);

  void *len_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype);
  int len = 0;
  generic_hton(len_send, &len, sizeof(int), 1);

  void *tag_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype) + sizeof(int);
  generic_hton(tag_send, &tag, sizeof(int), 1);

  void *seq_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                   (sizeof(int) * 2);
  unsigned long long seq = 0;
  generic_hton(seq_send, &seq, sizeof(unsigned long), 1);

  void *id_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                  sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                  (sizeof(int) * 2) + sizeof(unsigned long);
  generic_hton(id_send, &MPI_PROCESS->ids[dest][root], sizeof(unsigned long),
               1);

  void *buf_send = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                   (sizeof(int) * 2) + sizeof(unsigned long) +
                   sizeof(unsigned long);

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
    break;
  }

  ssize_t sent =
      pipe_send_all(MPI_PROCESS->socket_tcp_fd[dest], message, total_size);
  free(message);

  if (sent != total_size) {
    return -1;
  }

  return count;
}

int __mpi_recv_pipe(void *buf, int count, MPI_Datatype datatype, int source,
                    int tag) {
  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    return -1;
  }

  int total_size = MPI_HEADER + size;
  void *message = malloc(total_size);
  if (!message) {
    perror("malloc failed");
    return -1;
  }

  ssize_t received =
      pipe_recv_all(MPI_PROCESS->socket_tcp_fd[source], message, total_size);
  if (received < total_size) {
    free(message);
    printf("failed recv from pipe\n");
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
  void *len_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype);
  generic_ntoh(&len, len_recv, sizeof(int), 1);

  int tag_;
  void *tag_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype) + sizeof(int);
  generic_ntoh(&tag_, tag_recv, sizeof(int), 1);

  unsigned long seq;
  void *seq_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                   (sizeof(int) * 2);
  generic_ntoh(&seq, seq_recv, sizeof(unsigned long), 1);

  unsigned long id;
  void *id_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                  sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                  (sizeof(int) * 2) + sizeof(unsigned long);
  generic_ntoh(&id, id_recv, sizeof(unsigned long), 1);

  void *buf_recv = (char *)message + (sizeof(char) * 4) + (sizeof(int) * 3) +
                   sizeof(MPI_Collective) + sizeof(MPI_Datatype) +
                   (sizeof(int) * 2) + sizeof(unsigned long) +
                   sizeof(unsigned long);

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
  case MPI_SHORT:
    generic_ntoh(buf, buf_recv, sizeof(short), count);
    break;
  case MPI_UNSIGNED_SHORT:
    generic_ntoh(buf, buf_recv, sizeof(unsigned short), count);
    break;
  case MPI_INT:
    generic_ntoh(buf, buf_recv, sizeof(int), count);
    break;
  case MPI_UNSIGNED:
    generic_ntoh(buf, buf_recv, sizeof(unsigned), count);
    break;
  case MPI_LONG:
    generic_ntoh(buf, buf_recv, sizeof(long), count);
    break;
  case MPI_UNSIGNED_LONG:
    generic_ntoh(buf, buf_recv, sizeof(unsigned long), count);
    break;
  case MPI_LONG_LONG:
    generic_ntoh(buf, buf_recv, sizeof(long long), count);
    break;
  case MPI_UNSIGNED_LONG_LONG:
    generic_ntoh(buf, buf_recv, sizeof(unsigned long long), count);
    break;
  case MPI_FLOAT:
    generic_ntoh(buf, buf_recv, sizeof(float), count);
    break;
  case MPI_DOUBLE:
    generic_ntoh(buf, buf_recv, sizeof(double), count);
    break;
  case MPI_LONG_DOUBLE:
    generic_ntoh(buf, buf_recv, sizeof(long double), count);
    break;
  case MPI_C_BOOL:
    generic_ntoh(buf, buf_recv, sizeof(bool), count);
    break;
  case MPI_WCHAR: {
    generic_ntoh(buf, buf_recv, sizeof(wchar_t), count);
    wchar_t *buf_char = (wchar_t *)buf;
    buf_char[count] = L'\0';
  } break;
  default:
    break;
  }

  free(message);
  return count;
}

// Replace all __mpi_send_tcp calls with __mpi_send_pipe
// Replace all __mpi_recv_tcp calls with __mpi_recv_pipe

int mpi_barrier_ring(void) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;
  int dummy = 0;
  int tag = 9999;

  int next = (rank + 1) % size;
  int prev = (rank - 1 + size) % size;

  if (rank == 0) {
    __mpi_send_pipe(&dummy, 1, MPI_INT, rank, next, tag, MPI_SEND);
    __mpi_recv_pipe(&dummy, 1, MPI_INT, prev, tag);
  } else {
    __mpi_recv_pipe(&dummy, 1, MPI_INT, prev, tag);
    __mpi_send_pipe(&dummy, 1, MPI_INT, rank, next, tag, MPI_SEND);
  }

  return 0;
}

// Update mpi_send to use pipes for fallback
int mpi_send(const void *buf, int count, MPI_Datatype datatype, int dest,
             int tag) {
  int sent = 0;
  __mpi_send(buf, count, datatype, MPI_PROCESS->rank, dest, tag, MPI_SEND);

  void *message = malloc(MPI_HEADER);
  if (!message) {
    perror("malloc failed");
    return -1;
  }

  // Read ACK/NACK from pipe
  ssize_t err =
      pipe_recv_all(MPI_PROCESS->socket_tcp_fd[dest], message, MPI_HEADER);

  if (err < MPI_HEADER) {
    free(message);
    return -1;
  }

  MPI_Datatype __datatype;
  void *datatype_recv = (char *)message + (sizeof(char) * 4) +
                        (sizeof(int) * 3) + sizeof(MPI_Collective);
  generic_ntoh(&__datatype, datatype_recv, sizeof(MPI_Datatype), 1);

  int root;
  void *root_recv = (char *)message + (sizeof(char) * 4);
  generic_ntoh(&root, root_recv, sizeof(int), 1);

  if (__datatype == MPI_NACK) {
    sent = __mpi_send_pipe(buf, count, datatype, MPI_PROCESS->rank, root, tag,
                           MPI_SEND);
  }

  free(message);
  return sent;
}

// Continue with remaining functions, replacing TCP calls with pipe calls...
// [Rest of the code follows the same pattern]