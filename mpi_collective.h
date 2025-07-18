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
MPI_process_info *mpi_init(int rank);
void print_mpi_message(void *buf, int length, MPI_Datatype datatype);
int datatype_size_in_bytes(int count, MPI_Datatype datatype);
int mpi_send(const void *buf, int count, MPI_Datatype datatype, int dest,
             int tag);
int mpi_recv(void *buf, int count, MPI_Datatype datatype, int source, int tag);

int mpi_bcast(void *buf, int count, MPI_Datatype datatype, int root);
