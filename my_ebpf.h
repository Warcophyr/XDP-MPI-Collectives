#pragma once
#include "mpi_struct.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_common.h>
#include <bpf/libbpf_legacy.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <xdp/xsk.h>
// #include "my_ebpf.c"

// Initialize the loader
int ebpf_loader_init(struct ebpf_loader *loader);

// Load eBPF program from file
int ebpf_loader_load(struct ebpf_loader *loader, const char *filename);

// Attach program to a specific attach point by name
int ebpf_loader_attach_by_name(struct ebpf_loader *loader,
                               const char *interface_name);

// Attach program to a specific attach point by index
int ebpf_loader_attach_by_index(struct ebpf_loader *loader,
                                int interface_index);

// Detach and cleanup
void ebpf_loader_cleanup(struct ebpf_loader *loader);

// Get program file descriptor
int ebpf_loader_get_prog_fd(struct ebpf_loader *loader);

// Get map file descriptor by name
int ebpf_loader_get_map_fd(struct ebpf_loader *loader, const char *map_name);

int read_packets_from_map(int map_fd, struct ebpf_loader *loader);