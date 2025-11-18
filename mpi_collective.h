#pragma once
#define _GNU_SOURCE
#include <math.h>
#include <alloca.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <wait.h>
#include <stdbool.h>
#include <wchar.h>
#include <locale.h>
#include <sys/resource.h>
#include <net/if.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/socket.h>
// #include <ioctls.h>

// Raw socket includes - add these before other networking includes
// #include <linux/if_packet.h>  // For AF_PACKET
#include <linux/if_ether.h>   // For ETH_P_ALL
#include <netpacket/packet.h> // For sockaddr_ll structure

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>
#include "mpi_global_variable.h"
#include "mpi_struct.h"
#include "my_ebpf.h"
#include "hton.h"
#include "packet.h"
#include "mpi_collective.c"
#include "Wtime.h"
#include <math.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <xdp/libxdp.h>
#include <bpf/libbpf_legacy.h>

#include <netinet/tcp.h>

int extract_5tuple(int sockfd, struct socket_id *id);
int create_udp_socket(int port);
MPI_process_info *mpi_init(int rank, int mpi_sockets_map_fd,
                           int mpi_send_map_fd);
int datatype_size_in_bytes(int count, MPI_Datatype datatype);
void print_mpi_message(void *buf, int length, MPI_Datatype datatype);
int mpi_send(const void *buf, int count, MPI_Datatype datatype, int dest,
             int tag);
int mpi_recv(void *buf, int count, MPI_Datatype datatype, int source, int tag);

int mpi_barrier(void);

/* Enqueue `val` into queue `qid`. Returns 0 on success, -1 if full. */

int mpi_bcast(void *buf, int count, MPI_Datatype datatype, int root);

int mpi_bcast_ring(void *buf, int count, MPI_Datatype datatype, int root);