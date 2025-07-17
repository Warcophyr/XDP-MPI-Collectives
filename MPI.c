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
  // printf("%lu\n", sizeof(float));
  for (int i = 0; i < WORD_SIZE; i++) {
    pid_t pid = fork();
    if (pid == 0) {
      MPI_PROCESS = mpi_init(i);
      // printf("rank: %d\n", MPI_PROCESS->rank);
      if (MPI_PROCESS->rank == 1) {
        double msg[] = {1.1, 2.9, 3.3};
        mpi_send_v2(msg, 3, MPI_DOUBLE, 2, MPI_SEND);
      }
      if (MPI_PROCESS->rank == 2) {

        double msg[1024];
        mpi_recv_v2(msg, 3, MPI_DOUBLE, 1, MPI_ANY_TAG);
      }
      exit(EXIT_SUCCESS);
    }
  }

  while (wait(NULL) > 0)
    ;

  return EXIT_SUCCESS;
}
