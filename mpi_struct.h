#pragma once
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <xdp/xsk.h>

typedef struct Array {
  void *arr;
  size_t len;
} Array;

typedef enum MPI_Datatype {
  MPI_CHAR,
  MPI_SIGNED_CHAR,
  MPI_UNSIGNED_CHAR,
  MPI_SHORT,
  MPI_UNSIGNED_SHORT,
  MPI_INT,
  MPI_UNSIGNED,
  MPI_LONG,
  MPI_UNSIGNED_LONG,
  MPI_LONG_LONG,
  MPI_UNSIGNED_LONG_LONG,
  MPI_FLOAT,
  MPI_DOUBLE,
  MPI_LONG_DOUBLE,
  MPI_C_BOOL,
  MPI_WCHAR
} MPI_Datatype;

typedef enum MPI_Collective {
  MPI_SEND,
  MPI_BCAST,
  MPI_REDUCE,
  MPI_SHATTER,
  MPI_GATHER,
  MPI_SHATTERV,
  MPI_GATHERV
} MPI_Collective;

typedef enum MPI_Opcode {
  MPI_SUM,
  MPI_PROD,
  MPI_MAX,
  MPI_MIN,
  MPI_LAND,
  MPI_LOR,
  MPI_LXOR,
  MPI_BAND,
  MPI_BOR,
  MPI_BXOR,
  MPI_MAXLOC,
  MPI_MINLOC,
  MPI_REPLACE
} MPI_Opcode;

typedef struct MPI_process_info {
  int rank;
  int *socket_fd;
  int *socket_barrier_fd;
} MPI_process_info;

typedef struct socket_id {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol; // IPPROTO_TCP = 6
} socket_id;

typedef struct tuple_process {
  __u32 src_procc;
  __u32 dst_procc;
} tuple_process;

typedef struct ebpf_loader {
  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_link *link;
  int prog_fd;
} ebpf_loader;

struct sockaddr_info {
  __u16 sin_family;
  __u16 sin_port;
  __u32 sin_addr;
};

typedef struct EBPF_info {
  ebpf_loader *loader;
  int address_to_proc;
  int proc_to_address;
  int num_process;
} EBPF_info;
