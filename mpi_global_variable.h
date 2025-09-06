#pragma once
#include <stdlib.h>
#include "mpi_struct.h"
#include <xdp/xsk.h>

#define MPI_GLOVAL_VAR
#define BASE_PORT 5000
#define MAX_MESSAGE_SIZE 1024

EBPF_info EBPF_INFO = {0};
struct ebpf_loader loader = {0};

#define QUEUE_SIZE 128
#define QUEUE_MASK (QUEUE_SIZE - 1)

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define UMEM_SIZE (NUM_FRAMES * FRAME_SIZE)