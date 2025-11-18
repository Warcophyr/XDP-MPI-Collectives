#pragma once
#define _GNU_SOURCE
#include "mpi_global_variable.h"
#include "mpi_struct.h"
#include "mpi_collective.h"
#include "Wtime.h"
#include <sched.h>
#define PORT 5000
#define BUFFER_SIZE 1024
#define MAESTRALE_IP "192.168.101.2"
#define GRECALE_IP "192.168.101.1"

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

  // printf("Time: %lf \n", TTOTAL);

  // const size_t N = 10000000;
  // const size_t N = 8241000;
  // const size_t N = 4194304;
  // const size_t N = 7000000;
  const size_t N = 1048577;
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
    // const size_t N = 1425;
    // const size_t n = 65536;
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
    // char y[N];
    // for (int i = 0; i < N; i++) {
    //   y[i] = 'a'; // set each element to 'a'
    // }
    // y[N - 1] = '\0';
    // printf("z: %ld\n", strlen(z));
    fflush(stdout);
    fflush(stderr);
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
          for (int i = 0; i < CPU_SETSIZE; i++) {
            if (CPU_ISSET(i, &get_set)) {
              printf("  CPU %d\n", i);
            }
          }
        }

        // if (MPI_PROCESS->rank == 0) {
        //   // printf("MY_RANK: %d\n", MPI_PROCESS->rank);
        //   mpi_send(y, sizeof(y) / sizeof(char), MPI_CHAR, 1, 1);
        //   // __mpi_send_tcp_optimized(y, sizeof(y) / sizeof(char),
        //   // MPI_CHAR,
        //   //     // 1, 1);
        //   //     // __mpi_send_udp_optimized(y, sizeof(y) / sizeof(char),
        //   //     MPI_CHAR, 1,
        //   // 1,
        //   //                          MPI_SEND);
        //   // __mpi_send_tcp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0, 1,
        //   // 1,
        //   //                MPI_SEND);
        // }
        // if (MPI_PROCESS->rank == 1) {
        //   mpi_recv(y, sizeof(y) / sizeof(char), MPI_CHAR, 0, 1);
        //   // __mpi_recv_tcp_optimized(y, sizeof(y) / sizeof(char),
        //   // MPI_CHAR,
        //   //     // 0, 1);
        //   //     // __mpi_recv_udp_optimized(y, sizeof(y) / sizeof(char),
        //   //     MPI_CHAR, 0,
        //   // 1);
        //   // __mpi_recv_tcp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0,
        //   // 1);
        // }
        double diff = 0.0;
        double __diff = 0.0;
        double cpu_time_used = 0.0;
        for (size_t n = 2; n < N; n *= 2) {
          // for (size_t warmup = 0; warmup < 5; warmup++) {
          // char y[n];
          // for (int i = 0; i < n; i++) {
          //   y[i] = 'a';
          // }
          // if (MPI_PROCESS->rank == 0) {
          //   y[n - 2] = 'E';
          // }

          //   mpi_barrier_ring();
          //   mpi_bcast_ring_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);
          //   mpi_barrier_ring();
          // }

          double __cpu_time_used = 0.0;
          for (size_t _ = 0; _ < 10; _++) {
            /* code */

            if (n < 2) {
              exit(EXIT_FAILURE);
            }

            char y[n];
            for (int i = 0; i < n; i++) {
              y[i] = 'a'; // set each element to 'a'
            }
            y[n - 1] = '\0';

            if (MPI_PROCESS->rank == 0) {
              for (size_t i = 0; i < n - 1; i++) {
                y[i] = 'A';
              }
              y[n - 2] = 'E';
            }
            fflush(stdout);

            // TTOTAL = cp_Wtime();
            // double start = 0.0;
            clock_t start, end;
            // double cpu_time_used;
            // ttotal =  get_time(TTOTAL);
            mpi_barrier_ring();
            // usleep(10000); // 10ms settle
            start = clock();

            mpi_bcast_ring_xdp(&y, sizeof(y) / sizeof(char), MPI_CHAR, 0);

            end = clock();

            mpi_barrier_ring();
            // diff = end - start;
            __cpu_time_used += (((double)(end - start)) / CLOCKS_PER_SEC);
            // if (rank == 0) {
            //   // printf("Time: %lf, size: %d\n", diff, n);
            //   printf("Time: %lf, size: %d\n", cpu_time_used, n);
            // }

            // mpi_reduce_linear_sum(&cpu_time_used, &__cpu_time_used, 1, 0);
            // mpi_reduce_linear_max(&cpu_time_used, &__cpu_time_used, 1, 0);
            // if (rank == 0) {
            //   printf("Time: %lf, size: %d\n", __cpu_time_used, n);
            // }
            // mpi_reduce_ring(&__cpu_time_used, 1, MPI_DOUBLE, MPI_MAX, 0);
            // printf("rank: %d Time END: %lf buf: %ld\n", rank, diff, n);

            // mpi_reduce_ring(&diff, 1, MPI_DOUBLE, MPI_MAX, 0);
            // mpi_reduce_linear_max(&diff, &__diff, 1, 0);
            // if (rank == 0) {
            //   printf("RANK: %d, Time: %lf, size: %d\n", rank, __diff, n);
            // }
            // mpi_reduce_ring(&diff, 1, MPI_DOUBLE, MPI_SUM, 0);
            // double avg_time = diff / WORD_SIZE;
            // if (rank == 0) {
            //   printf("Time: %lf, size: %d\n", avg_time, n);
            // }
            // mpi_barrier_ring();
            // for (size_t r = 0; r < WORD_SIZE; r++) {
            //   mpi_barrier_ring();
            //   if (MPI_PROCESS->rank == r) {
            //     printf("Rank: %d: \n%s\n", MPI_PROCESS->rank, y);
            //     printf("\n");
            //     fflush(stdout);
            //   }
            //   mpi_barrier_ring();
            // }

            // if (rank == 0) {
            //   printf("Time: %lf, size: %d\n", diff, n);
            // }
            // sleep(1);
          }
          // if (rank == 0) {
          //   printf("Time: %lf, size: %d\n", __cpu_time_used / 10, n);
          // }

          mpi_reduce_linear_max(&__cpu_time_used, &cpu_time_used, 1, 0);

          if (rank == 0) {
            printf("Time: %lf, size: %d\n", cpu_time_used / 10, n);
          }
        }
        // }

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
        // if (MPI_PROCESS->rank == 1) {
        //   printf("Rank: %d: len: %ld \n%s\n", MPI_PROCESS->rank, strlen(y),
        //   y); printf("\n"); fflush(stdout);
        // }

        // if (MPI_PROCESS->rank == 0 || 1 || 2) {
        //   printf("Rank: %d: \n", MPI_PROCESS->rank);
        //   for (size_t i = 0; i < (sizeof(x) / sizeof(int)) - 1; i++) {
        //     printf("%d ", x[i]);
        //   }
        //   printf("\n");
        //   fflush(stdout);
        // }
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
  return EXIT_SUCCESS;
}
