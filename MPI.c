#include "mpi_global_variable.h"
#include "mpi_struct.h"
#include "mpi_collective.h"

int main(int argc, char *argv[]) {
  setlocale(LC_ALL, "");
  setlocale(LC_NUMERIC, "C.UTF-8");

  int option = 0;
  int option_index = 0;

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
      WORD_SIZE = val > 0 ? (size_t)val : 1;
      printf("You chose number of processes: %lu\n", WORD_SIZE);
      break;
    }
    case '?':
      perror("Unknown option. Use --help.\n");
      exit(EXIT_FAILURE);
    default:
      break;
    }
  }

  int err = 0;

  err = ebpf_loader_init(&loader);
  if (err != 0) {
    perror("loader init fail\n");
    exit(EXIT_FAILURE);
  }
  err = ebpf_loader_load(&loader, "xdp_map_mpi.o");
  if (err != 0) {
    perror("loader xdp.o fail\n");
    exit(EXIT_FAILURE);
  }

  err = ebpf_loader_attach_by_index(&loader, 2);
  if (err != 0) {
    perror("loader attach fail\n");
    exit(EXIT_FAILURE);
  }

  int mpi_socket_map_fd = ebpf_loader_get_map_fd(&loader, "mpi_sockets_map");
  int mpi_send_map_fd = ebpf_loader_get_map_fd(&loader, "mpi_send_map");
  int info_packet_arr_fd = ebpf_loader_get_map_fd(&loader, "info_packet_arr");
  int queue_fd = ebpf_loader_get_map_fd(&loader, "queue_map");
  int head_fd = ebpf_loader_get_map_fd(&loader, "head_map");
  int tail_fd = ebpf_loader_get_map_fd(&loader, "tail_map");
  int temp_packet_storage_fd =
      ebpf_loader_get_map_fd(&loader, "temp_packet_storage");
  int mpi_packet_queue_fd = ebpf_loader_get_map_fd(&loader, "mpi_packet_queue");

  EBPF_INFO.loader = &loader;
  EBPF_INFO.mpi_sockets_map_fd = mpi_socket_map_fd;
  EBPF_INFO.info_packet_arr_fd = info_packet_arr_fd;
  EBPF_INFO.mpi_send_map_fd = mpi_send_map_fd;
  EBPF_INFO.queue_map_fd = queue_fd;
  EBPF_INFO.head_map_fd = head_fd;
  EBPF_INFO.tail_map_fd = tail_fd;

  // char x[] = {'a', 'a', 'a', 'a'};
  int x[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  // char y[] = {'a', 'a', 'a', 'a'};
  for (int rank = 0; rank < WORD_SIZE; rank++) {
    pid_t pid = fork();
    if (pid == 0) {
      MPI_PROCESS = mpi_init(rank, EBPF_INFO.mpi_sockets_map_fd,
                             EBPF_INFO.mpi_send_map_fd);

      // if (MPI_PROCESS->rank == 0) {
      //   bpf_map_lookup_elem()
      // }
      if (MPI_PROCESS->rank == 1) {

        x[0] = 2;
        x[1] = 3;
        x[2] = 4;
        x[3] = 5;
        x[4] = 6;
        x[5] = 7;
        x[6] = 8;
        x[7] = 9;
        // y[0] = 'm';
        // y[1] = 'e';
        // y[2] = 'c';
        // y[3] = 'c';
        packet_info value = {0};
        // mpi_send_xdp(&x, sizeof(x) / sizeof(int), MPI_INT, 0, 2, &value);
        // mpi_send_raw(&x, sizeof(x), MPI_INT, 0, 2, &value);
        // mpi_send_xdp(&x, sizeof(x), MPI_CHAR, 0, 2, &value);
        // mpi_send_xdp(&x, sizeof(x), MPI_CHAR, 2, 2, &value);
        // mpi_send(x, sizeof(x), MPI_CHAR, 0, 2);
        // mpi_send_raw_blanch(&x, sizeof(x), MPI_CHAR, 2, 2, &value);
        // mpi_send_raw_blanch(&x, sizeof(x), MPI_CHAR, 0, 2, &value);
        // mpi_send(x, sizeof(x) / sizeof(int), MPI_INT, 0, 2);
        // mpi_send_xdp(&x, sizeof(x) / sizeof(int), MPI_INT, 2, 2, &value);
        // mpi_send_raw_blanch_v2(2, MPI_BCAST, MPI_INT, 9);
        // mpi_send_raw_blanch_v2(3, MPI_BCAST, MPI_INT, 9);
      }
      // if (MPI_PROCESS->rank == 0) {
      //   mpi_recv(x, sizeof(x) / sizeof(int), MPI_INT, 1, 2);
      // }
      // if (MPI_PROCESS->rank == 2) {
      //   mpi_recv(x, sizeof(x) / sizeof(int), MPI_INT, 1, 2);
      //   // mpi_send_raw_blanch_v2(3, MPI_BCAST, MPI_INT, 9);
      // }
      // if (MPI_PROCESS->rank == 3) {
      //   mpi_recv(x, sizeof(x) / sizeof(int), MPI_INT, 1, 2);
      // }
      fflush(stdout);
      mpi_bcast_ring(&x, sizeof(x) / sizeof(int), MPI_INT, 1);
      // mpi_bcast_ring_raw(&x, sizeof(x) / sizeof(int), MPI_INT, 1);
      // mpi_barrier();
      // mpi_bcast_ring_raw(&y, sizeof(y) / sizeof(char), MPI_CHAR, 1);
      // mpi_barrier();
      for (int i = 0; i < WORD_SIZE; i++) {
        wait(NULL); // wait for each child to finish
      }
      printf("Rank: %d: \n", MPI_PROCESS->rank);
      for (size_t i = 0; i < sizeof(x) / sizeof(int); i++) {
        printf("%d ", x[i]);
      }
      printf("\n");
      for (int i = 0; i < WORD_SIZE; i++) {
        wait(NULL); // wait for each child to finish
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
