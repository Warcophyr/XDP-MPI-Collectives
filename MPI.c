#define _GNU_SOURCE
#include "mpi_collective.h"
#include "mpi_global_variable.h"
#include "mpi_struct.h"
#include "my_ebpf.h"
#include <sched.h>
#include <string.h>
#include <unistd.h>

#define PORT 5000
#define BUFFER_SIZE 1024

FILE *fptr;
int N = 1000;
char outputname[64];
int warmup_iterations = 0;

#define GET_TIME()                                                             \
  ({                                                                           \
    struct timespec ts;                                                        \
    clock_gettime(CLOCK_MONOTONIC, &ts);                                       \
    (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;                              \
  })

int (*algo)(void *, int, MPI_Datatype, int) = &mpi_bcast_ring_xdp;

void help() {
  printf("Usage: ./mpi_collective [OPTIONS]\n");
  printf("Options:\n");
  printf("  -h, --help            Show this help message and exit\n");
  printf("  -o, --output FILE     Specify output file for results (default: "
         "test.csv)\n");
  printf("  -t, --tc              Use TC BPF program instead of XDP\n");
  printf("  -a, --algo ALGO       Choose algorithm (ring, linear, ring_eager) "
         "(default: ring)\n");
  printf("  -s, --size SIZE       Set the size of the data to broadcast "
         "(default: 1000)\n");
  printf("  -v, --version         Show version information and exit\n");
  printf("  -n, --np NUM          Set the number of processes (default: 1)\n");
  printf("  -i, --interface IFACE Specify network interface to attach BPF "
         "program (default: lo)\n");
  printf("  -w, --warmup ITER     Set the number of warmup iterations before "
         "measurement (default: 0)\n");
}

int main(int argc, char *argv[]) {
  setlocale(LC_ALL, "");
  setlocale(LC_NUMERIC, "C.UTF-8");

  int option = 0;
  int option_index = 0;
  char *interface = NULL;
  int use_tc = 0;
  char *bpf_prog_path = malloc(sizeof(char) * 64);
  strcpy(bpf_prog_path, "kfunc.bpf.o");

  static struct option long_option[] = {
      {"help", no_argument, 0, 'h'},
      {"output", required_argument, 0, 'o'},
      {"tc", no_argument, 0, 't'},
      {"algo", required_argument, 0, 'a'},
      {"size", required_argument, 0, 's'},
      {"version", no_argument, 0, 'v'},
      {"np", required_argument, 0, 'n'},
      {"interface", optional_argument, 0, 'i'},
      {"warmup", required_argument, 0, 'w'},
      {0, 0, 0, 0}};

  while ((option = getopt_long(argc, argv, "ho:v:n:i:ts:w:a:", long_option,
                               &option_index)) != -1) {
    switch (option) {
    case 'h':
      printf("Help option selected\n");
      break;
    case 'o':
      printf("Output file: %s\n", optarg);
      strncpy(outputname, optarg, sizeof(outputname) - 1);
      outputname[sizeof(outputname) - 1] = '\0';
      break;
    case 's':
      printf("Size option selected: %s\n", optarg);
      N = atoi(optarg);
      break;
    case 't':
      use_tc = 1;
      strcpy(bpf_prog_path, "bpf/tc/mpi_tc.bpf.o");
      if (access(bpf_prog_path, F_OK) != 0) {
        fprintf(stderr, "TC BPF program not found at %s\n", bpf_prog_path);
        exit(EXIT_FAILURE);
      }
      printf("TC option selected\n");
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
    case 'a':
      printf("Algorithm option selected: %s\n", optarg);
      if (strcmp(optarg, "ring") == 0) {
        algo = &mpi_bcast_ring_xdp;
      } else if (strcmp(optarg, "linear") == 0) {
        algo = &mpi_bcast_linear_xdp;
      } else if (strcmp(optarg, "ring_eager") == 0) {
        algo = &mpi_bcast_ring_xdp_eager;
      } else {
        fprintf(stderr, "Unknown algorithm: %s\n", optarg);
        exit(EXIT_FAILURE);
      }
      break;
    case 'w':
      warmup_iterations = atoi(optarg);
      printf("Warmup iterations: %d\n", warmup_iterations);
      break;
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

  if (strlen(outputname) == 0) {
    strcpy(outputname, "test.csv");
  }
  fptr = fopen(outputname, "a");
  if (fptr == NULL) {
    perror("Error opening output file");
    exit(EXIT_FAILURE);
  }

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
  // int n = recvfrom(sockfd, &number, sizeof(number), 0,
  //                  (struct sockaddr *)&cliaddr, &len);
  // if (n < 0) {
  //   perror("recvfrom");
  //   close(sockfd);
  //   exit(EXIT_FAILURE);
  // }

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

  err = ebpf_loader_load(&loader, bpf_prog_path);
  if (err != 0) {
    perror("loader xdp.o fail\n");
    exit(EXIT_FAILURE);
  }

  err = ebpf_loader_attach_by_name(&loader, interface);
  if (err != 0) {
    perror("loader attach fail\n");
    exit(EXIT_FAILURE);
  }

  int prog_id;
  struct bpf_prog_info info = {};
  __u32 info_len = sizeof(info);

  err = bpf_obj_get_info_by_fd(loader.prog_fd, &info, &info_len);
  if (err) {
    printf("Error getting program info: %d\n", err);
  }

  prog_id = info.id;
  printf("Loaded BPF program with ID: %d\n", prog_id);
  printf("Press Enter to continue...");
  // getchar();

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

  // printf("Time: %lf \n", TTOTAL);

  // const size_t N = 10000000;
  // const size_t N = 8241000;
  // const size_t N = 4194304;
  // const size_t N = 7000000;
  // const size_t N = 1048577;
  {

    // const size_t n = 8241000;
    // const size_t N = 5000000;
    // const size_t n = 2000000;
    // const size_t n = 1000000;
    // const size_t N = 50000;
    // const size_t n = 50000;
    // const size_t N = 60000;
    // const size_t N = 70000;
    // const size_t N = 80000;
    // const size_t N = 90000;
    // const size_t n = 524288;
    // const size_t n = 4;
    // const size_t n = 1048576;
    // const size_t N = 1000;
    // const size_t N = 65536;
    // const size_t n = 1048577;
    // const size_t N = 2850;
    // const size_t N = 99297;
    /* code */

    // char *y = malloc(N + 1);
    // if (y == NULL) {
    //   // perror("malloc fail\n");
    //   printf("malloc fail\n");
    //   exit(EXIT_FAILURE);
    // }
    char y[N];
    for (int i = 0; i < N; i++) {
      y[i] = 'a'; // set each element to 'a'
    }
    y[N - 1] = '\0';
    // printf("z: %ld\n", strlen(z));
    fflush(stdout);
    fflush(stderr);

    // @ciz get online CPU count
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);

    if (num_cpus < 1) {
      perror("Error getting number of CPUs");
      return 1;
    }

    for (int rank = 0; rank < WORD_SIZE; rank++) {
      pid_t pid = fork();
      if (pid == 0) {
        MPI_PROCESS = mpi_init(rank, EBPF_INFO.address_to_proc,
                               EBPF_INFO.proc_to_address);
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(rank, &set); // pin to CPU core 2 (0-based index)

        // Apply affinity to the current process (pid = 0)
        if (sched_setaffinity(0, sizeof(set), &set) == -1) {
          perror("sched_setaffinity");
          return 1;
        }
        cpu_set_t get_set;
        CPU_ZERO(&get_set);
        if (sched_getaffinity(0, sizeof(get_set), &get_set) == -1) {
          perror("sched_getaffinity");
        } else {
          printf("Child rank %d allowed CPUs:\n", rank);
          for (int i = 0; i < num_cpus; i++) {
            if (CPU_ISSET(i, &get_set)) {
              printf("  CPU %d\n", i);
            }
          }
        }

        if (MPI_PROCESS->rank == 0) {
          // printf("MY_RANK: %d\n", MPI_PROCESS->rank);
          // for (int i = 0; i < n; i++) {
          //   y[i] = 'a';
          // }
          // if (MPI_PROCESS->rank == 0) {
          y[N - 2] = 'E';
          // }
          // mpi_send(y, sizeof(y) / sizeof(char), MPI_CHAR, 1, 1);
          // __mpi_send_tcp_optimized(y, sizeof(y) / sizeof(char),
          // MPI_CHAR,
          //     // 1, 1);
          //     // __mpi_send_udp_optimized(y, sizeof(y) / sizeof(char),
          //     MPI_CHAR, 1,
          // 1,
          //                          MPI_SEND);
          // __mpi_send_tcp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0, 1,
          // 1,
          //                MPI_SEND);
        }
        if (MPI_PROCESS->rank == 1) {
          // mpi_recv(y, sizeof(y) / sizeof(char), MPI_CHAR, 0, 1);
          // __mpi_recv_tcp_optimized(y, sizeof(y) / sizeof(char),
          // MPI_CHAR,
          //     // 0, 1);
          //     // __mpi_recv_udp_optimized(y, sizeof(y) / sizeof(char),
          //     MPI_CHAR, 0,
          // 1);
          // __mpi_recv_tcp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0,
          // 1);
        }
        double diff = 0.0;
        double __diff = 0.0;
        double cpu_time_used = 0.0;
        // size_t n = N;
        // // for (size_t n = 2; n < N; n *= 2) {
        // // for (size_t warmup = 0; warmup < 5; warmup++) {
        // char y[n];
        // for (int i = 0; i < n; i++) {
        //   y[i] = 'a';
        // }
        // if (MPI_PROCESS->rank == 0) {
        //   y[n - 2] = 'E';
        // }

        mpi_barrier_ring();
        // Warmup phase
        for (int w = 0; w < warmup_iterations; w++) {
          // mpi_bcast_ring_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
          // mpi_bcast_ring_xdp_eager(&y, sizeof(y) / sizeof(char), MPI_CHAR,
          // 0); mpi_bcast_linear_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR,
          // 0); fprintf(stderr, "exit %d iteration %d\n", MPI_PROCESS->rank, w
          // + 1);
          algo(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
          mpi_barrier_ring();
          // if (MPI_PROCESS->rank == 0) {
          //   fprintf(stderr, "\n");
          // }
        }

        // fprintf(stderr, "Process %d completed warmup iterations\n",
        //         MPI_PROCESS->rank);

        // Actual measurement
        // clock_t start, end;

        // start = clock();
        double start = GET_TIME();
        // mpi_bcast_ring_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
        // mpi_bcast_ring_xdp_eager(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
        algo(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
        // mpi_bcast_linear_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
        double end = GET_TIME();

        mpi_barrier_ring();
        // mpi_bcast_ring_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
        // mpi_barrier_ring();
        // mpi_bcast_ring_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
        // mpi_barrier_ring();
        // mpi_bcast_ring_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
        // mpi_barrier_ring();
        // mpi_bcast_ring_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
        // mpi_barrier_ring();
        // end = clock();
        // Use write() for atomic file writes to avoid race conditions between
        // processes
        char timing_buffer[256];
        int bytes_written =
            snprintf(timing_buffer, sizeof(timing_buffer), "%d,%lf\n",
                     MPI_PROCESS->rank, (double)(end - start));
        if (bytes_written > 0) {
          write(fileno(fptr), timing_buffer, bytes_written);
        }

        fprintf(stderr, "Rank: %d  %lf sec\n", MPI_PROCESS->rank,
                (double)(end - start));

        // double __cpu_time_used = 0.0;
        // // for (size_t _ = 0; _ < 10; _++) {
        // /* code */

        // if (n < 2) {
        //   exit(EXIT_FAILURE);
        // }

        // char y[n];
        // for (int i = 0; i < n; i++) {
        //   y[i] = 'a'; // set each element to 'a'
        // }
        // y[n - 1] = '\0';

        // if (MPI_PROCESS->rank == 0) {
        //   for (size_t i = 0; i < n - 1; i++) {
        //     y[i] = 'A';
        //   }
        //   y[n - 2] = 'E';
        // }
        // fflush(stdout);

        // // TTOTAL = cp_Wtime();
        // // double start = 0.0;
        // clock_t start, end;
        // // double cpu_time_used;
        // // ttotal =  get_time(TTOTAL);
        // mpi_barrier_ring();
        // // usleep(10000); // 10ms settle
        // start = clock();

        // mpi_bcast_ring_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);

        // end = clock();

        // mpi_barrier_ring();
        // // diff = end - start;
        // __cpu_time_used += (((double)(end - start)) / CLOCKS_PER_SEC);
        // // if (rank == 0) {
        // //   // printf("Time: %lf, size: %d\n", diff, n);
        // //   printf("Time: %lf, size: %d\n", cpu_time_used, n);
        // // }

        // // mpi_reduce_linear_sum(&cpu_time_used, &__cpu_time_used, 1, 0);
        // // mpi_reduce_linear_max(&cpu_time_used, &__cpu_time_used, 1, 0);
        // // if (rank == 0) {
        // //   printf("Time: %lf, size: %d\n", __cpu_time_used, n);
        // // }
        // // mpi_reduce_ring(&__cpu_time_used, 1, MPI_DOUBLE, MPI_MAX, 0);
        // // printf("rank: %d Time END: %lf buf: %ld\n", rank, diff, n);

        // // mpi_reduce_ring(&diff, 1, MPI_DOUBLE, MPI_MAX, 0);
        // // mpi_reduce_linear_max(&diff, &__diff, 1, 0);
        // // if (rank == 0) {
        // //   printf("RANK: %d, Time: %lf, size: %d\n", rank, __diff, n);
        // // }
        // // mpi_reduce_ring(&diff, 1, MPI_DOUBLE, MPI_SUM, 0);
        // // double avg_time = diff / WORD_SIZE;
        // // if (rank == 0) {
        // //   printf("Time: %lf, size: %d\n", avg_time, n);
        // // }
        // // mpi_barrier_ring();
        // // for (size_t r = 0; r < WORD_SIZE; r++) {
        // //   mpi_barrier_ring();
        // //   if (MPI_PROCESS->rank == r) {
        // //     printf("Rank: %d: \n%s\n", MPI_PROCESS->rank, y);
        // //     printf("\n");
        // //     fflush(stdout);
        // //   }
        // //   mpi_barrier_ring();
        // // }

        // // if (rank == 0) {
        // //   printf("Time: %lf, size: %d\n", diff, n);
        // // }
        // // sleep(1);
        // // }
        // // if (rank == 0) {
        // //   printf("Time: %lf, size: %d\n", __cpu_time_used / 10, n);
        // // }

        // mpi_reduce_linear_max(&__cpu_time_used, &cpu_time_used, 1, 0);

        // if (rank == 0) {
        //   printf("Time: %lf, size: %d\n", cpu_time_used / 10, n);
        // }
        // }
        // }

        // if (MPI_PROCESS->rank == 0) {
        //   printf("end: %lf\n", ttotalend);
        // }
        // for (int i = 0; i < WORD_SIZE; i++) {
        //   wait(NULL); // wait for each child to finish
        // }
        // for (size_t r = 0; r < WORD_SIZE; r++) {
        //   mpi_barrier_ring();
        //   if (MPI_PROCESS->rank == r) {
        //     printf("Rank: %d: len: %ld \n%s\n", MPI_PROCESS->rank, strlen(y),
        //            y);
        //     // printf("\n");
        //   }
        //   printf("\n");
        //   // fflush(stdout);
        // }
        // mpi_barrier_ring();
        // if (MPI_PROCESS->rank == 1 || MPI_PROCESS->rank == 6) {
        // if (MPI_PROCESS->rank == 6) {
        //   printf("Rank: %d: len: %ld \n%s\n", MPI_PROCESS->rank, strlen(y),
        //   y); printf("\n"); fflush(stdout);
        // }

        // if (MPI_PROCESS->rank == 0 || 1 || 2) {
        //       printf("Rank: %d: \n", MPI_PROCESS->rank);
        //       for (size_t i = 0; i < (sizeof(x) / sizeof(int)) - 1; i++) {
        //         printf("%d ", x[i]);
        //       }
        //       printf("\n");
        //       fflush(stdout);
        //     }
        // for (int i = 0; i < WORD_SIZE; i++) {
        //   wait(NULL); // wait for each child to finish
        // }
        // ttotal = cp_Wtime() - TTOTAL;
        // if (rank == 0) {
        //   printf("Time: %lf \n", ttotal);
        // }

        exit(EXIT_SUCCESS);
      }
    }
  }

  while (wait(NULL) > 0)
    ;
  // pause();
  ebpf_loader_cleanup(&loader);
  free(bpf_prog_path);
  return EXIT_SUCCESS;
}
