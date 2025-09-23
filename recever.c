// receiver.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT1 5000
#define PORT2 5001
#define BUF_SIZE 1024

int main() {
  pid_t pid = fork();
  if (pid > 0) {
    int sockfd;
    int buffer[7];
    int number;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len = sizeof(cliaddr);

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
      perror("socket creation failed");
      exit(EXIT_FAILURE);
    }

    // Bind to any local address on PORT
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT1);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) <
        0) {
      perror("bind failed");
      close(sockfd);
      exit(EXIT_FAILURE);
    }

    printf("1 Receiver listening on port %d...\n", PORT1);

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
  } else if (pid == 0) {
    int sockfd;
    char buffer[BUF_SIZE];
    int number;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len = sizeof(cliaddr);

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
      perror("socket creation failed");
      exit(EXIT_FAILURE);
    }

    // Bind to any local address on PORT
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT2);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) <
        0) {
      perror("bind failed");
      close(sockfd);
      exit(EXIT_FAILURE);
    }

    printf("2 Receiver listening on port %d...\n", PORT2);

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

    printf("2 Received number: %d\n", number);

    close(sockfd);
  }
  // int sockfd;
  // int buffer[7];
  // int number;
  // struct sockaddr_in servaddr, cliaddr;
  // socklen_t len = sizeof(cliaddr);

  // // Create UDP socket
  // if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
  //   perror("socket creation failed");
  //   exit(EXIT_FAILURE);
  // }

  // // Bind to any local address on PORT
  // memset(&servaddr, 0, sizeof(servaddr));
  // servaddr.sin_family = AF_INET;
  // servaddr.sin_addr.s_addr = INADDR_ANY;
  // servaddr.sin_port = htons(PORT1);

  // if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
  // {
  //   perror("bind failed");
  //   close(sockfd);
  //   exit(EXIT_FAILURE);
  // }
  // while (1) {
  //   printf("1 Receiver listening on port %d...\n", PORT1);

  //   // Receive one message
  //   int n = recvfrom(sockfd, &number, sizeof(number), 0,
  //                    (struct sockaddr *)&cliaddr, &len);
  //   if (n < 0) {
  //     perror("recvfrom");
  //     close(sockfd);
  //     exit(EXIT_FAILURE);
  //   }

  //   //   buffer[n] = '\0'; // Null terminate
  //   //   printf("Received: %s\n", buffer);
  //   number = ntohl(number);
  //   printf("1 Received number: %d\n", number);
  //   // for (int i = 0; i < 7; i++) {
  //   //   printf("Received number: %d\n", buffer[i]);
  //   // }
  // }
  // close(sockfd);
  pause();
  return 0;
}