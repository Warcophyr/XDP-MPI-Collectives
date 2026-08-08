# XDP-MPI-Collectives

This project implements a small MPI-like broadcast benchmark that uses eBPF/XDP to accelerate collective communication. The main application starts several ranks as forked processes, loads a BPF program on a network interface, and runs a broadcast test using either the XDP or TC path.

## What each file is for

- MPI.c: entry point of the program. It parses command-line options, loads the BPF object, attaches it to the interface, populates the BPF maps, and forks the worker ranks.
- mpi_collective.c: contains the collective communication logic, including ring and linear broadcast implementations and the ACK/NACK fallback path.
- my_ebpf.c / my_ebpf.h: helper code for loading and attaching BPF programs and retrieving map file descriptors.
- bpf/xdp and bpf/tc: BPF programs for the supported execution modes.

## Requirements

Before running the system, make sure you have:

- a Linux machine with XDP support
- clang, gcc, make, and the usual build toolchain
- libbpf, libelf, zlib, and xdp-tools installed
- sudo privileges
- a valid network interface name, for example enp52s0f1np1

## Build the project

From the repository root, run:

```bash
make
```

This builds the main executable and the BPF objects.

## Basic usage

Run a broadcast test with 4 ranks on a specific interface:

```bash
sudo ./MPI -n 4 -i enp52s0f1np1
```

This uses the default XDP-based ring broadcast algorithm.

## Useful command-line options

- -n, --np: number of ranks to create
- -a, --algo: choose the broadcast algorithm: ring, linear, or ring_eager
- -s, --size: payload size in bytes
- -i, --interface: network interface to attach the BPF program to
- -o, --output: output CSV file for timing results
- -w, --warmup: number of warmup iterations before measurement
- -t, --tc: use the TC BPF program instead of XDP
- -z, --naive: disable the BPF path and use a naive userspace fallback
- -h, --help: show the help message

## Example commands

Run a linear broadcast with 8 ranks and a 4096-byte payload:

```bash
sudo ./MPI -n 8 -a linear -s 4096 -i enp52s0f1np1 -o results.csv
```

Run the same test with TC mode:

```bash
sudo ./MPI -n 8 -a linear -s 4096 -i enp52s0f1np1 -t -o results.csv
```

## Helpful debugging commands

- Inspect BPF trace output:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

- Show help:

```bash
sudo ./MPI -h
```

- Clean build artifacts:

```bash
make clean
```

## Output

The program appends timing results to the file specified with -o (or to test.csv by default). Each line contains timing information for one rank so you can analyze the broadcast performance later.
