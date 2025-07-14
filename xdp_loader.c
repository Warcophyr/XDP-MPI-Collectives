#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct ebpf_loader {
  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_link *link;
  int prog_fd;
};

// Initialize the loader
int ebpf_loader_init(struct ebpf_loader *loader) {
  memset(loader, 0, sizeof(*loader));

  // Set memory limit for eBPF
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit: %s\n",
            strerror(errno));
    return -1;
  }

  return 0;
}

// Load eBPF program from file
int ebpf_loader_load(struct ebpf_loader *loader, const char *filename) {
  int err;

  // Open BPF object file
  loader->obj = bpf_object__open_file(filename, NULL);
  if (libbpf_get_error(loader->obj)) {
    fprintf(stderr, "Failed to open BPF object file: %s\n", filename);
    return -1;
  }

  // Load BPF object into kernel
  err = bpf_object__load(loader->obj);
  if (err) {
    fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
    goto cleanup;
  }

  // Find the first program in the object
  loader->prog = bpf_object__next_program(loader->obj, NULL);
  if (!loader->prog) {
    fprintf(stderr, "No BPF program found in object file\n");
    err = -1;
    goto cleanup;
  }

  // Get program file descriptor
  loader->prog_fd = bpf_program__fd(loader->prog);
  if (loader->prog_fd < 0) {
    fprintf(stderr, "Failed to get program fd\n");
    err = -1;
    goto cleanup;
  }

  printf("Successfully loaded eBPF program from %s\n", filename);
  return 0;

cleanup:
  bpf_object__close(loader->obj);
  loader->obj = NULL;
  return err;
}

// Attach program to a specific attach point
int ebpf_loader_attach(struct ebpf_loader *loader,
                       enum bpf_attach_type attach_type,
                       const char *attach_point) {
  int err;

  if (!loader->prog) {
    fprintf(stderr, "No program loaded\n");
    return -1;
  }

  // For different program types, use different attach methods
  switch (bpf_program__type(loader->prog)) {
  case BPF_PROG_TYPE_KPROBE:
  case BPF_PROG_TYPE_TRACEPOINT:
    loader->link = bpf_program__attach(loader->prog);
    break;
  case BPF_PROG_TYPE_XDP:
    if (attach_point) {
      int ifindex = if_nametoindex(attach_point);
      if (ifindex == 0) {
        fprintf(stderr, "Invalid interface name: %s\n", attach_point);
        return -1;
      }
      loader->link = bpf_program__attach_xdp(loader->prog, ifindex);
    }
    break;
  case BPF_PROG_TYPE_SOCKET_FILTER:
    // Socket programs are attached differently
    printf("Socket filter program loaded, use prog_fd=%d to attach to socket\n",
           loader->prog_fd);
    return 0;
  default:
    loader->link = bpf_program__attach(loader->prog);
    break;
  }

  if (libbpf_get_error(loader->link)) {
    fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
    return -1;
  }

  printf("Successfully attached eBPF program\n");
  return 0;
}

// Detach and cleanup
void ebpf_loader_cleanup(struct ebpf_loader *loader) {
  if (loader->link) {
    bpf_link__destroy(loader->link);
    loader->link = NULL;
  }

  if (loader->obj) {
    bpf_object__close(loader->obj);
    loader->obj = NULL;
  }

  loader->prog = NULL;
  loader->prog_fd = -1;
}

// Get program file descriptor (useful for maps access)
int ebpf_loader_get_prog_fd(struct ebpf_loader *loader) {
  return loader->prog_fd;
}

// Get map file descriptor by name
int ebpf_loader_get_map_fd(struct ebpf_loader *loader, const char *map_name) {
  struct bpf_map *map;

  if (!loader->obj) {
    return -1;
  }

  map = bpf_object__find_map_by_name(loader->obj, map_name);
  if (!map) {
    fprintf(stderr, "Map '%s' not found\n", map_name);
    return -1;
  }

  return bpf_map__fd(map);
}

// Example usage
int main(int argc, char **argv) {
  struct ebpf_loader loader;
  int err;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <bpf_program.o> [interface_name]\n", argv[0]);
    return 1;
  }

  // Initialize loader
  err = ebpf_loader_init(&loader);
  if (err) {
    return 1;
  }

  // Load program
  err = ebpf_loader_load(&loader, argv[1]);
  if (err) {
    return 1;
  }

  // Attach program
  const char *attach_point = (argc > 2) ? argv[2] : NULL;
  err = ebpf_loader_attach(&loader, BPF_PROG_TYPE_UNSPEC, attach_point);
  if (err) {
    ebpf_loader_cleanup(&loader);
    return 1;
  }

  printf("Program loaded and attached successfully!\n");
  printf("Program FD: %d\n", ebpf_loader_get_prog_fd(&loader));

  // Keep running (in real usage, your program would do work here)
  printf("Press Ctrl+C to exit...\n");

  // Example: access a map if it exists
  int map_fd = ebpf_loader_get_map_fd(&loader, "my_map");
  if (map_fd >= 0) {
    printf("Found map 'my_map' with FD: %d\n", map_fd);
  }

  // Wait for signal
  pause();

  // Cleanup
  ebpf_loader_cleanup(&loader);
  return 0;
}
