#include "mpi_collective.h"
#include "hton.h"
#define _GNU_SOURCE
size_t WORD_SIZE = 1;
MPI_process_info *MPI_PROCESS = NULL;

int create_server_socket(int port) {
  int socket_fd;
  struct sockaddr_in addr;

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    perror("socket failed\n");
    exit(EXIT_FAILURE);
  }

  int opt = 1;
  setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind failed\n");
    exit(EXIT_FAILURE);
  }

  if (listen(socket_fd, WORD_SIZE) < 0) {
    perror("listen failed\n");
    exit(EXIT_FAILURE);
  }
  return socket_fd;
}

int connect_to_peer(int peer_rank, int my_rank) {
  int socket_fd;
  struct sockaddr_in addr;
  char ip[] = "127.0.0.1";
  int port = BASE_PORT + peer_rank;
  socket_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (socket_fd < 0) {
    perror("socket failed\n");
    exit(EXIT_FAILURE);
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, ip, &addr.sin_addr);

  while (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    usleep(100000); // wait 100ms
  }

  return socket_fd;
}

MPI_process_info *mpi_init(int rank) {
  MPI_process_info *mpi_process_info =
      (MPI_process_info *)malloc(WORD_SIZE * sizeof(MPI_process_info));
  if (mpi_process_info == NULL) {
    perror("calloc failed\n");
    exit(EXIT_FAILURE);
  }
  mpi_process_info->rank = rank;
  // printf("rank: %d\n", mpi_process_info->rank);

  int *sock_table = (int *)malloc(WORD_SIZE * sizeof(int));
  memset(sock_table, -1, sizeof(sock_table));

  int server_fd = create_server_socket(BASE_PORT + rank);

  for (int i = 0; i < WORD_SIZE; ++i) {
    if (i == rank)
      continue;

    if (rank < i) {
      sock_table[i] = connect_to_peer(i, rank);
    } else if (rank > i) {
      struct sockaddr_in cli_addr;
      socklen_t cli_len = sizeof(cli_addr);
      int conn_fd = accept(server_fd, (struct sockaddr *)&cli_addr, &cli_len);
      if (conn_fd < 0) {

        perror("fail accept\n");
        exit(EXIT_FAILURE);
      }
      sock_table[i] = conn_fd;
    }
  }
  mpi_process_info->socket_fd = sock_table;

  close(server_fd);

  sleep(1); // Wait until all peers are ready
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
  printf("rank: %d, tag: %d\n", MPI_PROCESS->rank, tag);
  void *tag_send = alloca(sizeof(tag));
  generic_hton(tag_send, &tag, sizeof(int), 1);
  send(MPI_PROCESS->socket_fd[dest], tag_send, sizeof(int), 0);
  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    // perror("can not send negative byte\n");
    // exit(EXIT_FAILURE);
    return -1;
  }
  void *buf_send = alloca(size);
  switch (datatype) {
  case MPI_CHAR: {
    generic_hton(buf_send, buf, sizeof(char), count);
  } break;
  case MPI_SIGNED_CHAR: {
    generic_hton(buf_send, buf, sizeof(signed char), count);
  } break;
  case MPI_UNSIGNED_CHAR: {
    generic_hton(buf_send, buf, sizeof(unsigned char), count);
  } break;
  case MPI_SHORT: {
    generic_hton(buf_send, buf, sizeof(short), count);
  } break;
  case MPI_UNSIGNED_SHORT: {
    generic_hton(buf_send, buf, sizeof(unsigned short), count);
  } break;
  case MPI_INT: {
    generic_hton(buf_send, buf, sizeof(int), count);
  } break;
  case MPI_UNSIGNED: {
    generic_hton(buf_send, buf, sizeof(unsigned), count);
  } break;
  case MPI_LONG: {
    generic_hton(buf_send, buf, sizeof(long), count);
  } break;
  case MPI_UNSIGNED_LONG: {
    generic_hton(buf_send, buf, sizeof(unsigned long), count);
  } break;
  case MPI_LONG_LONG: {
    generic_hton(buf_send, buf, sizeof(long long), count);
  } break;
  case MPI_UNSIGNED_LONG_LONG: {
    generic_hton(buf_send, buf, sizeof(unsigned long long), count);
  } break;
  case MPI_FLOAT: {
    generic_hton(buf_send, buf, sizeof(float), count);
  } break;
  case MPI_DOUBLE: {
    generic_hton(buf_send, buf, sizeof(double), count);
  } break;
  case MPI_LONG_DOUBLE: {
    generic_hton(buf_send, buf, sizeof(long double), count);
  } break;
  case MPI_C_BOOL: {
    generic_hton(buf_send, buf, sizeof(bool), count);
  } break;
  case MPI_WCHAR: {
    generic_hton(buf_send, buf, sizeof(wchar_t), count);
  } break;
  default:
    break;
  }
  send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
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
    unsigned short *arr_us = (short *)buf;
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
  void *tag_recv = alloca(sizeof(int));

  recv(MPI_PROCESS->socket_fd[source], tag_recv, sizeof(int), 0);

  int tag_int;
  generic_ntoh(&tag_int, tag_recv, sizeof(int), 1);
  if (tag_int != tag) {
    printf("rank: %d, tag_int: %d\n", MPI_PROCESS->rank, tag_int);
  }

  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    return -1;
  }

  // Allocate buffer for received data
  void *buf_recv = alloca(size);

  // Receive data into temporary buffer
  recv(MPI_PROCESS->socket_fd[source], buf_recv, size, 0);

  // Convert from network byte order to host byte order
  switch (datatype) {
  case MPI_CHAR: {
    generic_ntoh(buf, buf_recv, sizeof(char), count);
    // Add null terminator for string data
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
    break;
  }
  memcmp(buf, buf_recv, size);
  return count;
}
// In mpi_collective.c (and declare in mpi_collective.h):
int mpi_barrier(void) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;
  int parent = (rank - 1) / 2;
  int left_child = 2 * rank + 1;
  int right_child = 2 * rank + 2;
  int msg = 1;
  int rounds = 0;
  while ((1 << rounds) < size)
    rounds++;

  for (int r = 0; r < rounds; r++) {
    int partner_send = (rank + (1 << r)) % size;
    int partner_recv = (rank - (1 << r) + size) % size;

    // È sicuro fare Send poi Recv perché ogni round ha partner disgiunti
    mpi_send(&msg, 1, MPI_INT, partner_send, 0);
    mpi_recv(&msg, 1, MPI_INT, partner_recv, 0);
  }
  return 0;
}
int mpi_bcast(void *buf, int count, MPI_Datatype datatype, int root) {
  int rank = MPI_PROCESS->rank;
  int size = WORD_SIZE;

  // trasformo il rank in [0..size) con root→0
  int rel = (rank - root + size) % size;

  // log₂(size) round
  for (int step = 1, round = 0; step < size; step <<= 1, ++round) {
    int tag = 100; // tag unico per questo round

    if (rel < step) {
      int dst = rel + step;
      if (dst < size) {
        int real_dst = (dst + root) % size;
        mpi_send(buf, count, datatype, real_dst, tag);
      }
    } else if (rel < step * 2) {
      int src = rel - step;
      if (src >= 0) {
        int real_src = (src + root) % size;
        mpi_recv(buf, count, datatype, real_src, tag);
      }
    }
  }
  return 0;
}
