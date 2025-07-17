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

int mpi_send_v2(const void *buf, int count, MPI_Datatype datatype, int dest,
                MPI_Tag tag) {
  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    perror("can not send negative byte\n");
    exit(EXIT_FAILURE);
  }
  switch (datatype) {
  case MPI_CHAR: {
    send(MPI_PROCESS->socket_fd[dest], buf, size, 0);
  } break;
  case MPI_SIGNED_CHAR: {
    send(MPI_PROCESS->socket_fd[dest], buf, size, 0);
  } break;
  case MPI_UNSIGNED_CHAR: {
    send(MPI_PROCESS->socket_fd[dest], buf, size, 0);
  } break;
  case MPI_SHORT: {
    uint16_t buf_send[count];
    uint16_t *buf_int = (uint16_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htons(buf_int[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_UNSIGNED_SHORT: {
    uint16_t buf_send[count];
    uint16_t *buf_int = (uint16_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htons(buf_int[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_INT: {
    uint32_t buf_send[count];
    uint32_t *buf_int = (uint32_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htonl(buf_int[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_UNSIGNED: {
    uint32_t buf_send[count];
    uint32_t *buf_unsigned = (uint32_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htonl(buf_unsigned[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_LONG: {
    uint64_t buf_send[count];
    uint64_t *buf_long = (uint64_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htonll(buf_long[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_UNSIGNED_LONG: {
    uint64_t buf_send[count];
    uint64_t *buf_unsigned_long = (uint64_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htonll(buf_unsigned_long[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_LONG_LONG: {
    uint64_t buf_send[count];
    uint64_t *buf_long_long = (uint64_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htonll(buf_long_long[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_UNSIGNED_LONG_LONG: {
    uint64_t buf_send[count];
    uint64_t *buf_long_long = (uint64_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htonll(buf_long_long[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_FLOAT: {
    uint32_t buf_send[count];
    float *buf_float = (float *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htonf(buf_float[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_DOUBLE: {
    uint64_t buf_send[count];
    double *buf_long_long = (double *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htond(buf_long_long[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_LONG_DOUBLE: {
    uint128_t buf_send[count];
    long double *buf_long_long = (long double *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_send[i] = htonLd(buf_long_long[i]);
    }
    send(MPI_PROCESS->socket_fd[dest], buf_send, size, 0);
  } break;
  case MPI_C_BOOL:
    break;
  case MPI_WCHAR:
    break;
  default:
    break;
  }
  return 0;
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

int mpi_recv_v2(void *buf, int count, MPI_Datatype datatype, int source,
                MPI_Tag tag) {

  int size = datatype_size_in_bytes(count, datatype);
  if (size < 1) {
    perror("can not send negative byte\n");
    exit(EXIT_FAILURE);
  }
  recv(MPI_PROCESS->socket_fd[source], buf, size, 0);

  switch (datatype) {
  case MPI_CHAR: {
    print_mpi_message(buf, count, datatype);
  } break;
  case MPI_SIGNED_CHAR: {
    print_mpi_message(buf, count, datatype);
  } break;
  case MPI_UNSIGNED_CHAR: {
    print_mpi_message(buf, count, datatype);
  } break;
  case MPI_SHORT: {
    uint16_t buf_recv[count];
    short *buf_short = (short *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohs(buf_short[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_UNSIGNED_SHORT: {
    uint16_t buf_recv[count];
    unsigned short *buf_unsigned_short = (unsigned short *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohs(buf_unsigned_short[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_INT: {
    uint32_t buf_recv[count];
    int *buf_int = (int *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohl(buf_int[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_UNSIGNED: {
    uint32_t buf_recv[count];
    unsigned *buf_unsigned = (unsigned *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohl(buf_unsigned[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_LONG: {
    uint64_t buf_recv[count];
    long *buf_long = (long *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohll(buf_long[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_UNSIGNED_LONG: {
    uint64_t buf_recv[count];
    unsigned long *buf_unsigned_long = (unsigned long *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohll(buf_unsigned_long[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_LONG_LONG: {
    uint64_t buf_recv[count];
    long long *buf_long_long = (long long *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohll(buf_long_long[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_UNSIGNED_LONG_LONG: {
    uint64_t buf_recv[count];
    unsigned long long *buf_unsigned_long_long = (unsigned long long *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohll(buf_unsigned_long_long[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_FLOAT: {
    float buf_recv[count];
    uint32_t *buf_float = (uint32_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohf(buf_float[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_DOUBLE: {
    double buf_recv[count];
    uint64_t *buf_double = (uint64_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohd(buf_double[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_LONG_DOUBLE: {
    long double buf_recv[count];
    uint128_t *buf_long_double = (uint128_t *)buf;
    for (size_t i = 0; i < count; i++) {
      buf_recv[i] = ntohLd(buf_long_double[i]);
    }
    print_mpi_message(buf_recv, count, datatype);
  } break;
  case MPI_C_BOOL:
    break;
  case MPI_WCHAR:
    break;
  default:
    break;
  }

  return 0;
};

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