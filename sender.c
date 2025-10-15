// sender.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 5000
// #define SERVER_IP "100.82.216.62" // funziona ip preso tramite tailscale
// status intefacia enp52s0f1np1
#define SERVER_IP                                                              \
  "192.168.101.1" // non funziona ip preso tramite ip a intefacia enp52s0f1np1
// #define SERVER_IP "192.168.137.5" // funziona ip preso tramite ip a
// interfaccia eno1 di maestrale

int main() {
  int sockfd;
  struct sockaddr_in servaddr;
  //   const char *msg = "Hello UDP!";
  int number = 1;
  int net_number = htonl(number);

  // Create UDP socket
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, SERVER_IP, &servaddr.sin_addr) <= 0) {
    perror("invalid address");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  // Send message
  if (sendto(sockfd, &net_number, sizeof(number), 0,
             (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    perror("sendto");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  printf("Message sent: %d\n", number);

  close(sockfd);
  //   pause();
  return 0;
}
