#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <bpf/libbpf_legacy.h>
#include <bpf/libbpf_common.h>
#include <signal.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <time.h>
#include "mpi_struct.h"
#include "my_ebpf.c"

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