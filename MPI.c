#include "mpi_global_variable.h"
#include "mpi_struct.h"
#include "mpi_collective.h"
#define PORT 5000
#define BUFFER_SIZE 1024
#define MAESTRALE_IP "192.168.101.2"
#define GRECALE_IP "192.168.101.1"

double cp_Wtime() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + 1.0e-6 * tv.tv_usec;
}

int main(int argc, char *argv[]) {
  setlocale(LC_ALL, "");
  setlocale(LC_NUMERIC, "C.UTF-8");

  int option = 0;
  int option_index = 0;
  char *interface = NULL;

  static struct option long_option[] = {
      {"help", no_argument, 0, 'h'},
      {"output", required_argument, 0, 'o'},
      {"version", no_argument, 0, 'v'},
      {"np", required_argument, 0, 'n'},
      {"interface", optional_argument, 0, 'i'},
      {0, 0, 0, 0}};

  while ((option = getopt_long(argc, argv, "hov:n:i:", long_option,
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
      WORD_SIZE = val > 0 ? (size_t)val : 1;
      printf("You chose number of processes: %lu\n", WORD_SIZE);
      break;
    }
    case 'i': {
      if (optarg) {
        interface = strdup(optarg);
        if (!interface) {
          perror("strdup fail\n");
          exit(EXIT_FAILURE);
        }
      } else {
        interface = (char *)malloc(sizeof(char) * 3);
        interface[0] = 'l';
        interface[1] = 'o';
        interface[2] = '\0';
      }
    } break;
    case '?':
      perror("Unknown option. Use --help.\n");
      exit(EXIT_FAILURE);
    default:
      break;
    }
  }
  int sockfd;
  int buffer[7];
  struct sockaddr_in servaddr, cliaddr;
  socklen_t len = sizeof(cliaddr);
  //   const char *msg = "Hello UDP!";
  int number = 0;

  // Create UDP socket
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  // Bind to any local address on PORT
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(PORT);

  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    perror("bind failed");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  printf("MPI wait all process ready %d...\n", PORT);

  // Receive one message
  int n = recvfrom(sockfd, &number, sizeof(number), 0,
                   (struct sockaddr *)&cliaddr, &len);
  if (n < 0) {
    perror("recvfrom");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  //   buffer[n] = '\0'; // Null terminate
  //   printf("Received: %s\n", buffer);
  number = ntohl(number);
  printf("1 Received number: %d\n", number);
  // for (int i = 0; i < 7; i++) {
  //   printf("Received number: %d\n", buffer[i]);
  // }

  close(sockfd);

  int err = 0;

  err = ebpf_loader_init(&loader);
  if (err != 0) {
    perror("loader init fail\n");
    exit(EXIT_FAILURE);
  }
  err = ebpf_loader_load(&loader, "kfunc.bpf.o");
  if (err != 0) {
    perror("loader xdp.o fail\n");
    exit(EXIT_FAILURE);
  }

  err = ebpf_loader_attach_by_name(&loader, interface);
  if (err != 0) {
    perror("loader attach fail\n");
    exit(EXIT_FAILURE);
  }

  int adress_to_proc_fd = ebpf_loader_get_map_fd(&loader, "address_to_proc");
  int proc_to_adress_fd = ebpf_loader_get_map_fd(&loader, "proc_to_address");
  int num_process_fd = ebpf_loader_get_map_fd(&loader, "num_process");

  EBPF_INFO.loader = &loader;
  EBPF_INFO.address_to_proc = adress_to_proc_fd;
  EBPF_INFO.proc_to_address = proc_to_adress_fd;
  EBPF_INFO.num_process = num_process_fd;
  int key = 0;
  if (bpf_map_update_elem(num_process_fd, &key, &WORD_SIZE, BPF_ANY) != 0) {
    perror("fail update map num_process\n");
    exit(EXIT_FAILURE);
  }

  int x[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  // int x[] = {
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  //     1};

  const size_t N = 1451;
  char y[N];
  for (int i = 0; i < N; i++) {
    y[i] = 'a'; // set each element to 'a'
  }
  y[N - 1] = '\0';
  // printf("y: %d\n", strlen(y));
  for (int rank = 0; rank < WORD_SIZE; rank++) {
    pid_t pid = fork();
    if (pid == 0) {
      MPI_PROCESS =
          mpi_init(rank, EBPF_INFO.address_to_proc, EBPF_INFO.proc_to_address);
      // if (MPI_PROCESS->rank == 0) {
      //   bpf_map_lookup_elem()
      // }
      double ttotal = cp_Wtime();
      // if (MPI_PROCESS->rank == 0) {
      //   printf("start: %lf\n", ttotal);
      // }
      if (MPI_PROCESS->rank == 7) {

        x[0] = 2;
        x[1] = 3;
        x[2] = 4;
        x[3] = 5;
        x[4] = 6;
        x[5] = 7;
        x[6] = 8;
        x[7] = 9;
        // mpi_send(x, sizeof(x) / sizeof(int), MPI_INT, 0, 2);
        // y[0] = 'm';
        // y[1] = 'e';
        // y[2] = 'c';
        // y[3] = 'c';
        for (size_t i = 0; i < N - 1; i++) {
          y[i] = 'A';
        }
        y[N - 2] = 'E';

        // mpi_send_xdp(&x, sizeof(x) / sizeof(int), MPI_INT, 0, 2, &value);
        // mpi_send_raw(&x, sizeof(x), MPI_INT, 0, 2, &value);
        // mpi_send_xdp(&x, sizeof(x), MPI_CHAR, 0, 2, &value);
        // mpi_send_xdp(&x, sizeof(x), MPI_CHAR, 2, 2, &value);

        // mpi_send(y, sizeof(y) / sizeof(char), MPI_CHAR, 0, 1);

        // mpi_send_raw_blanch(&x, sizeof(x), MPI_CHAR, 2, 2, &value);
        // mpi_send_raw_blanch(&x, sizeof(x), MPI_CHAR, 0, 2, &value);
        // mpi_send(x, sizeof(x) / sizeof(int), MPI_INT, 0, 2);
        // mpi_send_xdp(&x, sizeof(x) / sizeof(int), MPI_INT, 2, 2, &value);
        // mpi_send_raw_blanch_v2(2, MPI_BCAST, MPI_INT, 9);
        // mpi_send_raw_blanch_v2(3, MPI_BCAST, MPI_INT, 9);
      }
      // if (MPI_PROCESS->rank == 0) {

      //   // TODO: implement ritrasmission in case of lost packet
      //   mpi_recv(y, sizeof(y) / sizeof(char), MPI_CHAR, 1, 1);
      // }
      // if (MPI_PROCESS->rank == 2) {
      //   mpi_recv(x, sizeof(x) / sizeof(int), MPI_INT, 1, 2);
      //   // mpi_send_raw_blanch_v2(3, MPI_BCAST, MPI_INT, 9);
      // }
      // if (MPI_PROCESS->rank == 3) {
      //   mpi_recv(x, sizeof(x) / sizeof(int), MPI_INT, 1, 2);
      // }
      fflush(stdout);
      // mpi_bcast_ring(&x, sizeof(x) / sizeof(int), MPI_INT, 1);
      // mpi_bcast_xdp(&x, sizeof(x) / sizeof(int), MPI_INT, 6);
      // mpi_bcast_ring_xdp(&x, sizeof(x) / sizeof(int), MPI_INT, 1);
      // // mpi_bcast_ring(&y, sizeof(y) / sizeof(char), MPI_CHAR, 1);
      mpi_bcast_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 7);
      // mpi_bcast(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
      // mpi_reduce_ring(&x, sizeof(x) / sizeof(int), MPI_INT, MPI_SUM, 1);
      // mpi_bcast_ring_raw(&x, sizeof(x) / sizeof(int), MPI_INT, 1);
      // mpi_barrier();
      // mpi_bcast_ring_raw(&y, sizeof(y) / sizeof(char), MPI_CHAR, 1);
      // mpi_barrier();
      ttotal = cp_Wtime() - ttotal;
      // if (MPI_PROCESS->rank == 0) {
      //   printf("end: %lf\n", ttotalend);
      // }
      // for (int i = 0; i < WORD_SIZE; i++) {
      //   wait(NULL); // wait for each child to finish
      // }
      // for (size_t r = 0; r < WORD_SIZE; r++) {
      //   // mpi_barrier_ring();
      //   if (MPI_PROCESS->rank == r) {
      //     printf("Rank: %d: \n", MPI_PROCESS->rank);
      //     for (size_t i = 0; i < (sizeof(x) / sizeof(int)) - 1; i++) {
      //       printf("%d ", x[i]);
      //     }
      //     printf("\n");
      //     fflush(stdout);
      //   }
      //   // mpi_barrier_ring();
      // }
      // mpi_barrier_ring();
      for (size_t r = 0; r < WORD_SIZE; r++) {
        // mpi_barrier_ring();
        if (MPI_PROCESS->rank == r) {
          printf("Rank: %d: \n%s\n", MPI_PROCESS->rank, y);
          printf("\n");
          fflush(stdout);
        }
        // mpi_barrier_ring();
      }
      // if (MPI_PROCESS->rank == 0) {
      //   printf("Rank: %d: len: %d \n%s\n", MPI_PROCESS->rank, strlen(y), y);
      //   printf("\n");
      //   fflush(stdout);
      // }
      // for (int i = 0; i < WORD_SIZE; i++) {
      //   wait(NULL); // wait for each child to finish
      // }
      if (rank == 0) {
        printf("Time: %lf \n", ttotal);
      }
      // printf("Rank: %d: \n", MPI_PROCESS->rank);
      // for (size_t i = 0; i < sizeof(y) / sizeof(char); i++) {
      //   printf("%c ", y[i]);
      // }
      // printf("\n");

      // read_packets_from_map(EBPF_INFO.mpi_sockets_map_fd, &loader);
      // mpi_barrier();
      // if (MPI_PROCESS->rank == 1) {
      //   int msg[] = {1, 2, 3};
      //   mpi_send(msg, 3, MPI_INT, 2, 1);
      // }
      // if (MPI_PROCESS->rank == 2) {

      //   int msg[1024];
      //   mpi_recv(msg, 3, MPI_INT, 1, 2);
      //   // printf("%s\n", msg);
      //   print_mpi_message(msg, 3, MPI_INT);
      // }
      exit(EXIT_SUCCESS);
    }
  }

  while (wait(NULL) > 0)
    ;
  // pause();
  ebpf_loader_cleanup(&loader);
  return EXIT_SUCCESS;
}
