#pragma once
#include <stdlib.h>
#include "mpi_struct.h"
#include <xdp/xsk.h>

#define MPI_ANY_SOURCE -2
#define MPI_ANY_TAG -1
#define MPI_TAG_UB 32179

#define PORT 5000
#define BUFFER_SIZE 1024
#define MAESTRALE_IP "192.168.101.2"
#define GRECALE_IP "192.168.101.1"

#define MPI_GLOVAL_VAR
#define BASE_PORT 5000
#define FALL_BACK_PORT 7000
#define MAX_PAYLOAD 1472
#define MPI_HEADER                                                             \
  ((sizeof(char) * 4) + (sizeof(int) * 3) + sizeof(MPI_Collective) +           \
   sizeof(MPI_Datatype) + (sizeof(int) * 2) + sizeof(unsigned long) +          \
   sizeof(unsigned long))
#define PAYLOAD_SIZE (MAX_PAYLOAD - MPI_HEADER)

EBPF_info EBPF_INFO = {0};
struct ebpf_loader loader = {0};
