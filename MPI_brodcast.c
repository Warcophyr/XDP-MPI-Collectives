#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BASE_PORT 5000
#define MAX_MESSAGE_SIZE 1024

// typedef struct MPI_process_info {
//   int fd;
//   struct sockaddr_in *info;
// } MPI_process_info;

typedef struct mpi_msg_header {
  int32_t src;
  int32_t dest;
  int32_t tag;
  int32_t length;
} mpi_msg_header;

int create_server_socket(int port, size_t num_process) {
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

  if (listen(socket_fd, num_process) < 0) {
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
void send_message(int fd, int src, int dest, const char *msg) {
  mpi_msg_header hdr = {src, dest, 0, strlen(msg)};
  send(fd, &hdr, sizeof(hdr), 0);
  send(fd, msg, hdr.length, 0);
}

void receive_message(int fd, int num_process) {
  mpi_msg_header hdr;
  char buffer[MAX_MESSAGE_SIZE + 1];

  ssize_t n = recv(fd, &hdr, sizeof(hdr), 0);
  if (n <= 0)
    return;

  recv(fd, buffer, hdr.length, 0);
  buffer[hdr.length] = '\0';
  printf("Rank %d received from %d: %s\n", hdr.dest, hdr.src, buffer);
};

void run_rank(int rank, int num_process) {
  int sock_table[num_process];
  memset(sock_table, -1, sizeof(sock_table));

  int server_fd = create_server_socket(BASE_PORT + rank, num_process);

  for (int i = 0; i < num_process; ++i) {
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

  close(server_fd);

  sleep(1); // Wait until all peers are ready

  // Example: only rank 0 sends message to all
  if (rank == 0) {
    for (int i = 1; i < num_process; i++) {
      char msg[100];
      snprintf(msg, sizeof(msg), "Hello from rank 0 to %d", i);
      send_message(sock_table[i], 0, i, msg);
    }
  }

  // Receive messages from any peer
  for (int i = 0; i < num_process; i++) {
    if (rank != 0 && sock_table[0] != -1) {
      receive_message(sock_table[0], num_process);
    }
  }

  for (int i = 0; i < num_process; i++) {
    if (sock_table[i] != -1)
      close(sock_table[i]);
  }

  exit(0);
}

int main(int argc, char *argv[]) {
  int option;
  int option_index = 0;
  size_t num_process = 1;

  static struct option long_option[] = {{"help", no_argument, 0, 'h'},
                                        {"output", required_argument, 0, 'o'},
                                        {"version", no_argument, 0, 'v'},
                                        {"np", required_argument, 0, 'n'},
                                        {0, 0, 0, 0}};

  while ((option = getopt_long(argc, argv, "hov:n:", long_option,
                               &option_index)) != -1) {
    switch (option) {
    case 'h':
      printf("Help option selected\n");
      break;
    case 'o':
      printf("Output file: %s\n", optarg);
      break;
    case 'v':
      printf("Version 1.0\n");
      break;
    case 'n': {
      char *endptr;
      errno = 0;
      long long val = strtoll(optarg, &endptr, 10);
      if (*endptr != '\0' || errno != 0) {
        fprintf(stderr, "Invalid number for --np: %s\n", optarg);
        exit(EXIT_FAILURE);
      }
      num_process = val > 0 ? (size_t)val : 1;
      printf("You chose number of processes: %lu\n", num_process);
      break;
    }
    case '?':
      fprintf(stderr, "Unknown option. Use --help.\n");
      exit(EXIT_FAILURE);
    default:
      break;
    }
  }

  for (int i = 0; i < num_process; i++) {
    pid_t pid = fork();
    if (pid == 0) {
      run_rank(i, num_process);
    }
  }

  // Parent waits for all ranks to finish
  while (wait(NULL) > 0)
    ;

  return EXIT_SUCCESS;
}
