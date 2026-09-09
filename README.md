# XDP-MPI-Collectives

This project implements a small MPI-like broadcast benchmark that uses eBPF/XDP to accelerate collective communication. The main application starts several ranks as forked processes, loads a BPF program on a network interface, and runs a broadcast test using either XDP or TC paths.

## What each file is for

- MPI.c: entry point of the program. It parses command-line options, loads the BPF object, attaches it to the interface, populates the BPF maps, and forks the worker ranks.
- mpi_collective.c: contains the collective communication logic, including ring and linear broadcast implementations and the ACK/NACK fallback path.
- my_ebpf.c / my_ebpf.h: helper code for loading and attaching BPF programs and retrieving map file descriptors.
- bpf/xdp, bpf/tc: BPF programs for the supported execution modes.

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

## Inline TX header (`inline-*` algorithms)

Every copy of a broadcast has to be given the next hop's headers: the two MACs
swapped, the next hop's 5-tuple in the IP and UDP headers, and its src/dst
ranks in the MPI header. That is 58 bytes at the front of the frame, and up to
now the BPF program wrote them into the packet itself, folding an IP checksum
over packet memory on every copy.

The `inline-*` algorithms have the NIC write them instead. The program builds
those 58 bytes in the copy's own metadata area and stamps a three-word
descriptor in front of them; the driver hands the bytes to the hardware as the
WQE inline header and leaves the packet's first 58 bytes out of the DMA, so the
NIC puts the new header on the wire in place of the old one and the frame keeps
its length. The packet is never written to.

It is the same collective, the same wire format and the same `mirror` on the
other side — only who writes the header changes, which is why the two can be
compared directly:

```bash
sudo ./MPI -n 8 -a inline-linear -s 1024 -i enp52s0f1np1
```

`inline-ring`, `inline-linear` and `inline-ring_eager` all exist, and each
selects `bpf/xdp/mpi_xdp_inline.bpf.o` — the same source as
`bpf/xdp/mpi_xdp.bpf.o`, compiled with `-DAXDP_INLINE` (see `forward_copy()`).
They are XDP-only: there is no TX offload to ask for on the TC path (`-t`) or
with the userspace fallback (`-z`).

### Requirements

The inline header is a feature of the out-of-tree mlx5 driver in
`../mellanox-clone-xdp`, and it needs the multi-packet WQE path off:

```bash
cd ../mellanox-clone-xdp/mellanox-out-of-tree-clone/mlx5/core
make reload
sudo ethtool --set-priv-flags enp52s0f1np1 rx_striding_rq off
sudo ethtool --set-priv-flags enp52s0f1np1 xdp_tx_mpwqe off
```

## Running the benchmark suite

`run_tests.py` takes several algorithms at once and runs every one of them
against every `-p`/`-n`/`-s` combination, in a single suite. Measuring the
inline and the software datapath back to back is the point: same governor, same
steering, same machine state, one invocation.

```bash
sudo /home/cizzo/base/bin/python ./run_tests.py \
    -n 4 8 16 32 -w 100 -s 1024 -i enp52s0f1np1 -r 10 --base-port 5000 \
    -p XDP -a linear inline-linear ring inline-ring
```

Results land in `results_<timestamp>/`, with one CSV column per combination
labelled `s=<size>_np=<n>_p=<prog>_a=<algo>`, a `stats_` CSV beside it and one
plot per size, grouped by `<prog>/<algo>`. Without `-p XDP` the default
`naive TC XDP` is used and the `inline-*` combinations for `naive` and `TC` are
skipped with a note, since they cannot exist.

### The other machine

The ranks all send to `GRECALE_IP` (192.168.101.2) and every copy has to come
back, so grecale runs `mirror`: an XDP program that swaps the MACs and the IP
addresses of anything arriving from 192.168.101.1 and returns it with `XDP_TX`,
leaving the UDP ports — which is what steers each copy to its rank — alone. It
is unchanged by all this: an inline-header frame reaches the wire like any
other.

```bash
# on grecale
cd ~/xdp-clone/XDP-MPI-Collectives/mirror
make mirror BPFTOOL=/usr/lib/linux-tools/6.11.0-25-generic/bpftool
sudo ./mirror enp172s0f0np0
```

(`BPFTOOL` only because Ubuntu's `/usr/sbin/bpftool` wrapper refuses to run
when there is no `linux-tools` package for the running kernel.)
