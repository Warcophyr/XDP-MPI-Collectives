#include "../mpi_global_variable.h"
#include "../my_ebpf.h"
#include <alloca.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wait.h>
#include <wchar.h>

#define PORT 5000
#define BUFFER_SIZE 1024
#define MAESTRALE_IP "192.168.101.1"
// #define MAESTRALE_IP "192.168.101.10"
#define GRECALE_IP "192.168.101.2"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {

  setlocale(LC_ALL, "");
  setlocale(LC_NUMERIC, "C.UTF-8");
  libbpf_set_print(libbpf_print_fn);
  int option = 0;
  int option_index = 0;
  char *interface = NULL;

  static struct option long_option[] = {
      {"interface", required_argument, 0, 'f'}, {0, 0, 0, 0}};

  while ((option = getopt_long(argc, argv, "i:", long_option, &option_index)) !=
         -1) {
    switch (option) {
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

  int err = 0;

  err = ebpf_loader_init(&loader);
  if (err != 0) {
    perror("loader init fail\n");
    exit(EXIT_FAILURE);
  }
  err = ebpf_loader_load(&loader, "mirror.bpf.o");
  if (err != 0) {
    perror("loader xdp.o fail\n");
    exit(EXIT_FAILURE);
  }

  err = ebpf_loader_attach_by_name(&loader, interface);
  if (err != 0) {
    perror("loader attach fail\n");
    exit(EXIT_FAILURE);
  }

  int sockfd;
  // int buffer[7];
  int number;
  struct sockaddr_in servaddr;
  // struct sockaddr_in cliaddr;
  // socklen_t len = sizeof(cliaddr);

  //   const char *msg = "Hello UDP!";
  number = 1;
  int net_number = htonl(number);

  // Create UDP socket
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, MAESTRALE_IP, &servaddr.sin_addr) <= 0) {
    perror("invalid address");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  // Send message
  // if (sendto(sockfd, &net_number, sizeof(number), 0,
  //            (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
  //   perror("sendto");
  //   close(sockfd);
  //   exit(EXIT_FAILURE);
  // }

  // printf("Message sent: %d\n", number);
  //
  close(sockfd);

  // int MPI_IP_TABLE_FD = ebpf_loader_get_map_fd(&loader, "MPI_IP_TABLE");
  pause();
  ebpf_loader_cleanup(&loader);
  return 0;
}