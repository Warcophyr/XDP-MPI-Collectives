#include "mpi_collective.h"
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

int size_type(int count, MPI_Datatype datatype) {
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

void mpi_send(int fd, int src, int dest, const char *msg) {
  mpi_msg_header hdr = {src, dest, 0, strlen(msg)};
  send(fd, &hdr, sizeof(hdr), 0);
  send(fd, msg, hdr.length, 0);
}

int mpi_send_v2(const void *buf, int count, MPI_Datatype datatype, int dest,
                MPI_Tag tag) {
  count = size_type(count, datatype);
  if (count < 0) {
    perror("can not send negative byte\n");
    exit(EXIT_FAILURE);
  }
  mpi_msg_header hdr = {MPI_PROCESS->rank, dest, tag, count, datatype};

  send(MPI_PROCESS->socket_fd[dest], &hdr, sizeof(hdr), 0);
  send(MPI_PROCESS->socket_fd[dest], buf, hdr.length, 0);
}

void mpi_recv(int fd) {
  mpi_msg_header hdr;
  char buffer[MAX_MESSAGE_SIZE + 1];

  ssize_t n = recv(fd, &hdr, sizeof(hdr), 0);
  if (n <= 0)
    return;

  recv(fd, buffer, hdr.length, 0);
  buffer[hdr.length] = '\0';
  printf("Rank %d received from %d: %s\n", hdr.dest, hdr.src, buffer);
};

void print_mpi_message(void *buf, int length, MPI_Datatype datatype) {
  switch (datatype) {
  case MPI_CHAR:
    char *arr = (char *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%c", arr[i]);
    }
    printf("\n");

    break;
  case MPI_SIGNED_CHAR:
    signed char *arr = (signed char *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%hhd", arr[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED_CHAR:
    unsigned char *arr = (unsigned char *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%hhu", arr[i]);
    }
    printf("\n");
    break;
  case MPI_SHORT:
    short *arr = (short *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%hd", arr[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED_SHORT:
    unsigned short *arr = (short *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%hu", arr[i]);
    }
    printf("\n");
    break;
  case MPI_INT:
    int *arr = (int *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%d", arr[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED:
    unsigned *arr = (unsigned *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%u", arr[i]);
    }
    printf("\n");
    break;
  case MPI_LONG:
    long *arr = (long *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%ld", arr[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED_LONG:
    unsigned long *arr = (unsigned long *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%lu", arr[i]);
    }
    printf("\n");
    break;
  case MPI_LONG_LONG:
    long long *arr = (long long *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%lld", arr[i]);
    }
    printf("\n");
    break;
  case MPI_UNSIGNED_LONG_LONG:
    unsigned long long *arr = (unsigned long long *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%llu", arr[i]);
    }
    printf("\n");
    break;
  case MPI_FLOAT:
    float *arr = (float *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%f", arr[i]);
    }
    printf("\n");
    break;
  case MPI_DOUBLE:
    double *arr = (double *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%f", arr[i]);
    }
    printf("\n");
    break;
  case MPI_LONG_DOUBLE:
    long double *arr = (long double *)buf;
    for (size_t i = 0; i < length; i++) {
      printf("%Lf", arr[i]);
    }
    printf("\n");
    break;
  case MPI_C_BOOL:
    bool *arr = (bool *)buf;
    if (arr[0]) {
      printf("True\n");
    } else {
      printf("False\n");
    }
    break;
  case MPI_WCHAR:
    long double *arr = (long double *)buf;
    for (size_t i = 0; i < length; i++) {
      wprintf(L"%lc", arr[i]);
    }
    wprintf(L"\n");
    break;
  default:
    break;
  }
}

void mpi_recv_v2(void *buf, int count, MPI_Datatype datatype, int source,
                 MPI_Tag tag) {
  mpi_msg_header hdr;

  ssize_t n = recv(MPI_PROCESS->socket_fd[source], &hdr, sizeof(hdr), 0);
  if (n <= 0)
    return;

  void *buffer = alloca(hdr.length + 1);
  recv(MPI_PROCESS->socket_fd[source], buffer, hdr.length, 0);
  // buffer[hdr.length] = '\0';

  printf("Rank %d received from %d: %s\n", hdr.dest, hdr.src, buffer);
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

  int *sock_table = (int *)calloc(WORD_SIZE, sizeof(int));
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

  // // Example: only rank 0 sends message to all
  // if (rank == 0) {
  //   for (int i = 1; i < WORD_SIZE; i++) {
  //     char msg[100];
  //     snprintf(msg, sizeof(msg), "Hello from rank 0 to %d", i);
  //     send_message(mpi_process_info->socket_fd[i], 0, i, msg);
  //   }
  // }

  // // Receive messages from any peer
  // for (int i = 0; i < WORD_SIZE; i++) {
  //   if (rank != 0 && mpi_process_info->socket_fd[0] != -1) {
  //     receive_message(mpi_process_info->socket_fd[0], WORD_SIZE);
  //   }
  // }

  // for (int i = 0; i < WORD_SIZE; i++) {
  //   if (mpi_process_info->socket_fd[i] != -1)
  //     close(mpi_process_info->socket_fd[i]);
  // }

  // exit(EXIT_SUCCESS);
  return mpi_process_info;
}