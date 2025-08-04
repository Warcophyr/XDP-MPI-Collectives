#include "my_ebpf.h"

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
int ebpf_loader_attach_by_name(struct ebpf_loader *loader,
                               const char *interface_name) {
  if (!loader->prog) {
    fprintf(stderr, "No program loaded\n");
    return -1;
  }

  // For XDP programs, attach to interface
  if (bpf_program__type(loader->prog) == BPF_PROG_TYPE_XDP) {
    if (!interface_name) {
      fprintf(stderr, "Interface name required for XDP programs\n");
      return -1;
    }

    int ifindex = if_nametoindex(interface_name);
    if (ifindex == 0) {
      fprintf(stderr, "Invalid interface name: %s\n", interface_name);
      return -1;
    }

    loader->link = bpf_program__attach_xdp(loader->prog, ifindex);
    if (libbpf_get_error(loader->link)) {
      fprintf(stderr, "Failed to attach XDP program to %s: %s\n",
              interface_name, strerror(errno));
      return -1;
    }

    printf("Successfully attached XDP program to interface %s\n",
           interface_name);
  } else {
    // For other program types, use generic attach
    loader->link = bpf_program__attach(loader->prog);
    if (libbpf_get_error(loader->link)) {
      fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
      return -1;
    }

    printf("Successfully attached BPF program\n");
  }

  return 0;
}
int ebpf_loader_attach_by_index(struct ebpf_loader *loader,
                                int interface_index) {
  if (!loader->prog) {
    fprintf(stderr, "No program loaded\n");
    return -1;
  }

  // For XDP programs, attach to interface
  if (bpf_program__type(loader->prog) == BPF_PROG_TYPE_XDP) {

    loader->link = bpf_program__attach_xdp(loader->prog, interface_index);
    if (libbpf_get_error(loader->link)) {
      fprintf(stderr, "Failed to attach XDP program to %d: %s\n",
              interface_index, strerror(errno));
      return -1;
    }

    printf("Successfully attached XDP program to interface %d\n",
           interface_index);
  } else {
    // For other program types, use generic attach
    loader->link = bpf_program__attach(loader->prog);
    if (libbpf_get_error(loader->link)) {
      fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
      return -1;
    }

    printf("Successfully attached BPF program\n");
  }

  return 0;
}

// Detach and cleanup
void ebpf_loader_cleanup(struct ebpf_loader *loader, char *maps_name,
                         int num_maps) {
  if (maps_name != NULL) {
    // for (size_t i = 0; i < num_maps; i++) {
    char path[] = "/sys/fs/bpf/";
    char path_file[strlen(path) + strlen(maps_name) + 1];

    // Use snprintf for safer string concatenation
    snprintf(path_file, sizeof(path_file), "%s%s", path, maps_name);
    // if (loader->obj) {
    //   if (bpf_object__unpin_maps(loader->obj, path_file) < 0) {
    //     fprintf(stderr, "WARNING: failed unpin_maps: %s\n", strerror(errno));
    //   }
    // }

    // 2) Make sure the pin file itself is gone
    if (access(path_file, F_OK) == 0) {
      if (unlink(path_file) < 0) {
        fprintf(stderr, "WARNING: unlink(%s) failed: %s\n", path_file,
                strerror(errno));
      }
    }
    // }
  }
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

// Get program file descriptor
int ebpf_loader_get_prog_fd(struct ebpf_loader *loader) {
  return loader->prog_fd;
}

// Get map file descriptor by name
int ebpf_loader_get_map_fd(struct ebpf_loader *loader, const char *map_name) {
  struct bpf_map *map;

  if (!loader->obj) {
    return -1;
  }
  char path[] = "/sys/fs/bpf/";
  // Allocate enough space: path length + map_name length + null terminator
  char path_file[strlen(path) + strlen(map_name) + 1];

  // Use snprintf for safer string concatenation
  snprintf(path_file, sizeof(path_file), "%s%s", path, map_name);
  // if (access(path_file, F_OK) == 0) {
  //   remove(path_file);
  // }

  map = bpf_object__find_map_by_name(loader->obj, map_name);
  if (!map) {
    fprintf(stderr, "Map '%s' not found\n", map_name);
    return -1;
  }
  printf("load map: %s\n", map_name);

  return bpf_map__fd(map);
}

int read_packets_from_map(int map_fd, struct ebpf_loader *loader) {
  socket_id key = {0};
  socket_id next_key = {0};
  tuple_process value = {0};
  int num_socket = 0;

  printf("Reading packets from map...\n");

  // Iterate through map entries
  while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
    if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
      printf("ip info found:\n \
              src_ip: %u\n \
              dst_ip: %u\n \
              src_port: %d\n \
              dst_port: %d\n \
              protocol: %d\n \
              src: %d\n \
              dst: %d\n",
             next_key.src_ip, next_key.dst_ip, next_key.src_port,
             next_key.dst_port, next_key.protocol, value.src_procc,
             value.dst_procc);

      // Process the packet (modify, clone, inject, etc.)
      // This is where you'd implement your packet cloning logic

      num_socket++;
    }
    key = next_key;
  }
  printf("===================\n");

  return num_socket;
}