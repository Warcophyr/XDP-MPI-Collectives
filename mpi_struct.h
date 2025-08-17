#pragma once
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_link.h>

#define MPI_ANY_TAG 0
#define MPI_TAG_UB 32179
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

typedef enum MPI_Opcode {
  MPI_BCAST,
  MPI_REDUCE,
  MPI_SHATTER,
  MPI_GATHER,
  MPI_SHATTERV,
  MPI_GATHERV
} MPI_Opcode;

typedef struct MPI_process_info {
  int rank;
  int *socket_fd;
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
  int mpi_sockets_map_fd;
  int info_packet_arr_fd;
  int mpi_send_map_fd;
  int queue_map_fd;
  int head_map_fd;
  int tail_map_fd;
} EBPF_info;

typedef struct packet_info {
  __u32 ingress_ifindex;
  __u8 eth_hdr[14]; // Ethernet header
  __u8 ip_hdr[20];  // IPv4 header (no options)
  __u8 udp_hdr[8];  // UDP header
  __u32 total_len;  // e.g. ntohs(ip->tot_len)
                    // … you can add seq numbers, timestamps, etc.
} packet_info;

typedef struct inject_packet {
  __u32 target_ifindex;   // Interface to inject to
  __u32 packet_len;       // Length of the packet
  __u8 packet_data[1500]; // Packet data (max MTU)
} inject_packet;