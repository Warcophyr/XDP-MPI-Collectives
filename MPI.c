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

  err = ebpf_loader_attach_by_index(&loader, 1);
  if (err != 0) {
    perror("loader attach fail\n");
    exit(EXIT_FAILURE);
  }

  struct ring_buffer *rb = NULL;

  int mpi_socket_map_fd = ebpf_loader_get_map_fd(&loader, "mpi_sockets_map");
  int mpi_send_map_fd = ebpf_loader_get_map_fd(&loader, "mpi_send_map");
  int info_packet_arr_fd = ebpf_loader_get_map_fd(&loader, "info_packet_arr");
  int queue_fd = ebpf_loader_get_map_fd(&loader, "queue_map");
  int head_fd = ebpf_loader_get_map_fd(&loader, "head_map");
  int tail_fd = ebpf_loader_get_map_fd(&loader, "tail_map");

  EBPF_INFO.loader = &loader;
  EBPF_INFO.mpi_sockets_map_fd = mpi_socket_map_fd;
  EBPF_INFO.info_packet_arr_fd = mpi_send_map_fd;
  EBPF_INFO.mpi_send_map_fd = info_packet_arr_fd;
  EBPF_INFO.queue_map_fd = queue_fd;
  EBPF_INFO.head_map_fd = head_fd;
  EBPF_INFO.tail_map_fd = tail_fd;

  char x[] = {'a', 'a', 'a'};
  for (int rank = 0; rank < WORD_SIZE; rank++) {
    pid_t pid = fork();
    if (pid == 0) {
      MPI_PROCESS = mpi_init(rank, EBPF_INFO.mpi_sockets_map_fd,
                             EBPF_INFO.mpi_send_map_fd);
      if (MPI_PROCESS->rank == 1) {

        x[0] = 'm';
        x[1] = 'e';
        x[2] = 'c';
        packet_info value = {0};
        mpi_send_xdp(&x, sizeof(x), MPI_CHAR, 0, 2, &value);
        // mpi_send(x, sizeof(x), MPI_CHAR, 0, 2);
      }
      if (MPI_PROCESS->rank == 0) {
        mpi_recv(x, sizeof(x), MPI_CHAR, 1, 2);
      }
      fflush(stdout);
      // // mpi_barrier();
      // mpi_bcast(&x, 3, MPI_CHAR, 1);
      // if (MPI_PROCESS->rank == 0) {
      // ring_buffer__poll(rb, 100);
      // }
      // mpi_barrier();
      printf("Rank: %d: \n", MPI_PROCESS->rank);
      for (size_t i = 0; i < 3; i++) {
        printf("%c ", x[i]);
      }
      printf("\n");

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
  ebpf_loader_cleanup(&loader);
  return EXIT_SUCCESS;
}
