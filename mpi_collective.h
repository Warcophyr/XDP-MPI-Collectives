#ifndef SOCKET_H
#define SOCKET_H
#include <alloca.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <wait.h>
#include <stdbool.h>
#include <wchar.h>
#include <locale.h>
#include "mpi_global_variable.h"
#include "mpi_struct.h"
#include "mpi_collective.c"
#endif

int create_server_socket(int port);
int connect_to_peer(int peer_rank, int my_rank);
void mpi_send(int fd, int src, int dest, const char *msg);
void mpi_recv(int fd);
MPI_process_info *mpi_init(int rank);