# XDP-MPI-Collectives — Project Agent Guide

## Overview

This project implements a simplified MPI-like collective communication library that leverages the XDP packet-cloning feature described in [`mellanox-clone-xdp/AGENT.md`](../mellanox-clone-xdp/AGENT.md).

The core idea: instead of having the root process send `N-1` separate UDP packets, the root sends **one UDP packet** into the XDP clone path. The NIC driver and BPF program handle all forwarding in kernel space, without returning to userspace per hop.

- **Ring broadcast** — chain reaction: each hop clones once, the copy walks the ring.
- **Linear broadcast** — fan-out: root's first recipient creates `size` copies simultaneously, one per remaining rank.

Every receiver **always** sends a TCP ACK back to the root. The root waits for all `N-1` ACKs and retransmits via TCP on NACK.

All processes run as **forked children** of a single parent, each pinned to a dedicated CPU core and communicating over UDP (data) + TCP (ACK/retransmit fallback).

---

## Repository Context

```
XDP_CLONE/
├── mellanox-clone-xdp/              # Custom mlx5 driver with XDP_CLONE_PASS / XDP_CLONE_TX
│   └── AGENT.md                     # XDP clone driver reference
└── XDP-MPI-Collectives/             # This project
    ├── MPI.c                        # Entry point: node init, BPF load, collective dispatch
    ├── mpi_collective.c             # Collective implementations
    ├── kfunc.bpf.c                  # XDP BPF program: clone trigger + per-copy forwarding
    ├── mpi_collective.h
    ├── mpi_struct.h                 # MPI process state, socket structures
    ├── mpi_global_variable.h        # Shared globals (WORD_SIZE, MPI_PROCESS, etc.)
    └── my_ebpf.h                    # ebpf_loader_* wrappers
```

---

## Process Initialization — `MPI.c`

### CLI Arguments

| Flag | Long flag | Default | Effect |
|------|-----------|---------|--------|
| `-n` | `--np` | 1 | Number of MPI ranks (`WORD_SIZE`) |
| `-a` | `--algo` | `ring` | Algorithm: `ring`, `linear`, `ring_eager` |
| `-s` | `--size` | 1000 | Payload size in bytes |
| `-i` | `--interface` | `lo` | Network interface to attach BPF program |
| `-o` | `--output` | `test.csv` | Output CSV file for timing results |
| `-w` | `--warmup` | 0 | Warmup iterations before measurement |
| `-t` | `--tc` | off | Use TC BPF instead of XDP (`bpf/tc/mpi_tc.bpf.o`) |

### Startup Sequence

1. Parse CLI, select algorithm function pointer `algo`.
2. Open output CSV file.
3. `ebpf_loader_init` → `ebpf_loader_load("kfunc.bpf.o")` → `ebpf_loader_attach_by_name(interface)` — loads the XDP BPF program onto the NIC.
4. Retrieve three BPF map FDs: `address_to_proc`, `proc_to_address`, `num_process`.
5. Write `WORD_SIZE` into the `num_process` BPF map.
6. **`fork()` one child per rank** (0..WORD_SIZE-1), pin each child to CPU core `rank` via `sched_setaffinity`.
7. Each child calls `mpi_init(rank, address_to_proc_fd, proc_to_address_fd)`:
   - Opens UDP data socket at `BASE_PORT + rank` and ACK socket at `ACK_PORT + rank`.
   - Builds peer address tables (`peer_addrs[]`) all pointing to `GRECALE_IP`.
   - Opens TCP server on `FALL_BACK_PORT + rank` and does all-pairs TCP connect/accept.
   - Populates BPF maps `address_to_proc` and `proc_to_address` with 5-tuple↔rank mappings.
8. Child runs: warmup loop → barrier → `algo()` → barrier → write timing CSV → exit.
9. Parent waits for all children, then `ebpf_loader_cleanup`.

### Algorithm Selection

```c
int (*algo)(void *, int, MPI_Datatype, int) = &mpi_bcast_ring_xdp;  // default
// -a ring       → mpi_bcast_ring_xdp
// -a linear     → mpi_bcast_linear_xdp
// -a ring_eager → mpi_bcast_ring_xdp_eager
```

---

## Transport Layer

### Data Path (UDP)

All bulk data travels over a single per-rank UDP socket (`udp_socket_fd`). Every message carries a custom wire header (all fields in network byte order):

| Field | Type | Size |
|-------|------|------|
| Magic `"MPI\0"` | `char[4]` | 4 B |
| `root` | `int` | 4 B |
| `src` | `int` | 4 B |
| `dst` | `int` | 4 B |
| `collective` (opcode) | `MPI_Collective` | 4 B |
| `datatype` | `MPI_Datatype` | 4 B |
| `len` | `int` | 4 B |
| `tag` | `int` | 4 B |
| `seq` | `unsigned long` | 8 B |
| `id` | `unsigned long` | 8 B |
| payload | variable | — |

Total header = `MPI_HEADER`. Large messages are fragmented into `PAYLOAD_SIZE`-byte chunks with incrementing `seq`.

The BPF program (`kfunc.bpf.c`) reads this header directly from the UDP payload to parse `root`, `src`, `dst`, and `opcode`.

### Control Path (TCP — ACK invariant)

**Every receiver always responds back.** After every `mpi_recv`, the receiver sends a `MPI_ACK` (or `MPI_NACK`) header-only message to the root via the full-mesh TCP socket table. The root always waits for all `N-1` ACKs before returning from the collective. On NACK, root retransmits the full payload directly over TCP to that rank.

The TCP sockets are never used for bulk data in the XDP-accelerated paths — only for ACK/NACK and retransmit fallback.

### Key Constants

| Symbol | Meaning |
|--------|---------|
| `BASE_PORT` | UDP data port base; rank `r` listens on `BASE_PORT + r` |
| `ACK_PORT` | ACK UDP port base |
| `FALL_BACK_PORT` | TCP retransmit fallback port base |
| `PAYLOAD_SIZE` | Maximum UDP payload per fragment |
| `MAX_PAYLOAD` | Maximum single UDP datagram (`MPI_HEADER + PAYLOAD_SIZE`) |
| `MPI_HEADER` | Wire header size in bytes |
| `GRECALE_IP` | Remote machine IP (`192.168.101.2`); all peer UDP addresses point here |
| `MAESTRALE_IP` | Local machine IP (`192.168.101.1`) |
| `WORD_SIZE` | Number of MPI processes |

---

## BPF Program — `kfunc.bpf.c`

This is the XDP program loaded on the NIC. It is the kernel-side engine that triggers cloning and steers each copy to its correct destination.

### BPF Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `num_process` | `ARRAY[1]` | `__u32` index | `__u64` | Total number of MPI ranks |
| `address_to_proc` | `HASH[1024]` | `socket_id` (5-tuple) | `tuple_process` (src/dst rank) | Resolve incoming 5-tuple to rank pair |
| `proc_to_address` | `HASH[1024]` | `tuple_process` (src/dst rank) | `socket_id` (5-tuple) | Resolve rank pair to wire 5-tuple for forwarding |

### Entry Point: `kfunc`

The program only acts on UDP packets from `src_ip == 192.168.101.2` (GRECALE_IP). All other packets are `XDP_PASS`'d immediately.

Once an MPI/UDP packet is identified, the program dispatches on **metadata presence**:

```
iph->saddr == GRECALE_IP
├── metadata present (data_meta + 4 <= data)  →  handle_clone()   [copy, ID ≥ 1]
└── no metadata                               →  handle_original() [original, ID = 0]
```

### `handle_original` — triggers cloning

Called on the original packet (no metadata, written by the driver for ID=0). Parses the full MPI header from the UDP payload and dispatches on `opcode`:

| Opcode | Condition | Action |
|--------|-----------|--------|
| `MPI_SEND` | — | `XDP_PASS` (point-to-point, no clone) |
| `MPI_BCAST_RING` | `root == dst` | `XDP_PASS` (packet already at root) |
| `MPI_BCAST_RING` | otherwise | `XDP_CLONE_PASS(1)` — 1 copy created |
| `MPI_BCAST_LINEAR` | `root == dst` | `XDP_PASS` |
| `MPI_BCAST_LINEAR` | `root == src` (root sent it) | `XDP_CLONE_PASS(size)` — `size` copies created |
| `MPI_BCAST_LINEAR` | otherwise | `XDP_PASS` |

`XDP_CLONE_PASS(N)` means: original is **passed to the local UDP stack** (received by the target rank's socket), and N copies are created — each dispatched through `handle_clone` with metadata ID 1..N.

### `handle_clone` — steers each copy to its destination

Called once per copy, with `iter_copy` = the XDP metadata ID (1, 2, ..., N). The packet content is still the original (all copies are `memcpy`'d from the original `va` before any BPF run — see driver AGENT.md).

**For `MPI_BCAST_RING` and `MPI_BCAST_LINEAR`** (identical logic):

```c
next = (dst_host + iter_copy) % size
if (root_host == next)  →  XDP_PASS  // would loop back to root — stop here
```

If `next` is valid:
1. Look up `proc_to_address[{dst_host, next}]` — gets the target 5-tuple from the BPF map.
2. If not found: `XDP_PASS` (no registered address for this hop — silently drop).
3. If found: rewrite the packet in-place:
   - Swap Ethernet src/dst MACs.
   - Update MPI header `src_payload = dst_host`, `dst_payload = next`.
   - Set `udph->source`, `udph->dest`, `udph->check = 0`.
   - Set `iph->saddr`, `iph->daddr`, recompute `iph->check`.
4. Return `XDP_TX` — transmit the rewritten copy out of the NIC.

The rewritten packet re-enters the NIC RX path and triggers `handle_original` again for the next hop.

---

## Collective Algorithms

### `mpi_bcast_ring_xdp` — Ring Broadcast

**File:** `mpi_collective.c:2695`

**Topology:** logical ring — rank 0 → 1 → 2 → … → N-1.

**Full data-plane flow for N=4, root=0:**

```
Root sends 1 UDP packet: src=0, dst=1, opcode=MPI_BCAST_RING
                                         ↓
                               handle_original → XDP_CLONE_PASS(1)
                                         ↓
               ┌─────────────────────────┴──────────────────────────┐
               │ original (ID=0)                        copy (ID=1) │
               ↓                                                     ↓
     rank 1 receives via UDP                          handle_clone: next=(1+1)%4=2
         → sends TCP ACK to root                      rewrite headers → XDP_TX
                                                                     ↓
                                                     packet re-enters NIC: src=GRECALE, dst=2
                                                     handle_original → XDP_CLONE_PASS(1)
                                                               ↓
                                              ┌────────────────┴──────────────┐
                                              │ original (ID=0)    copy (ID=1) │
                                              ↓                                ↓
                                    rank 2 receives            handle_clone: next=(2+1)%4=3
                                    → sends TCP ACK            rewrite → XDP_TX
                                                                               ↓
                                                               handle_original: dst=3
                                                               XDP_CLONE_PASS(1)
                                                               original → rank 3 receives
                                                                         → sends TCP ACK
                                                               copy: next=(3+1)%4=0=root
                                                               root_host==next → XDP_PASS (stop)
```

Each hop is handled entirely within the NIC. Userspace (rank i) only does `mpi_recv` — the ring propagation requires zero additional userspace sends.

**Userspace root flow:**
1. `__mpi_send(buf, count, datatype, root, next=1, tag, MPI_BCAST_RING)` — one UDP send.
2. For each non-root rank `i` (0-indexed): blocking `recv(socket_tcp_fd[i])` waiting for TCP ACK/NACK.
   - On `MPI_NACK`: `__mpi_send_tcp(buf, ..., root=i)` — full TCP retransmit to rank `i`.

**Userspace non-root flow:**
1. `mpi_recv(buf, count, datatype, prev, tag)` — receive from ring predecessor.
2. `mpi_recv` sends `MPI_ACK` to root over TCP on success, `MPI_NACK` on packet loss.

---

### `mpi_bcast_linear_xdp` — Linear Broadcast (Fan-Out)

**File:** `mpi_collective.c:2801`

**Topology:** root sends to rank 1; rank 1's arrival triggers a simultaneous fan-out to all remaining ranks via `size` copies.

**Full data-plane flow for N=4, root=0:**

```
Root sends 1 UDP packet: src=0, dst=1, opcode=MPI_BCAST_LINEAR
                                         ↓
               handle_original: root(0)==src(0) → XDP_CLONE_PASS(size=4)
                         ↓
      ┌──────────────────┬─────────────────┬─────────────────┬──────────────────┐
      │ original (ID=0)  │   copy (ID=1)   │   copy (ID=2)   │   copy (ID=3)    │  copy (ID=4)
      ↓                  ↓                 ↓                 ↓                  ↓
rank 1 recv        handle_clone      handle_clone      handle_clone       handle_clone
→ TCP ACK    next=(1+1)%4=2    next=(1+2)%4=3    next=(1+3)%4=0     next=(1+4)%4=1
             rewrite→XDP_TX    rewrite→XDP_TX    root==next→XDP_PASS  lookup {1,1}→NULL
                  ↓                 ↓                                  → XDP_PASS (no-op)
             rank 2 recv       rank 3 recv
             → TCP ACK         → TCP ACK
```

All non-root ranks are reached in **a single NIC operation** — no chain reaction, no per-hop latency. The cost of the extra copy (ID=4, which duplicates rank 1) is silently discarded via a failed map lookup.

**Userspace flows:** identical to `mpi_bcast_ring_xdp` — root sends one UDP packet, waits for N-1 TCP ACKs; non-roots call `mpi_recv` and ACK back.

---

## Build and Run

```bash
cd XDP-MPI-Collectives
make                        # compile MPI.c + mpi_collective.c + kfunc.bpf.o
```

```bash
# Run with 4 processes, ring algorithm, 1000-byte payload on interface eth0
./mpi_collective -n 4 -a ring -s 1000 -i eth0 -o results.csv -w 5
```

The custom mlx5 driver **must already be loaded** before attaching the BPF program:
```bash
cd ../mellanox-clone-xdp/mellanox-out-of-tree-clone/mlx5/core
make reload    # loads driver + sets ethtool flags for XDP clone path
```

---

## Key Symbols

| Symbol | File | Purpose |
|--------|------|---------|
| `algo` | `MPI.c:25` | Function pointer to selected broadcast algorithm |
| `WORD_SIZE` | `mpi_global_variable.h` | Number of MPI processes |
| `MPI_PROCESS` | `mpi_global_variable.h` | Per-rank state (sockets, rank, buffers, ids) |
| `mpi_init` | `mpi_collective.c:159` | Per-rank socket setup + BPF map population |
| `mpi_bcast_ring_xdp` | `mpi_collective.c:2695` | Ring broadcast using XDP clone (default algo) |
| `mpi_bcast_linear_xdp` | `mpi_collective.c:2801` | Linear broadcast using XDP clone |
| `__mpi_send` | `mpi_collective.c:919` | Internal UDP send with fragmentation |
| `mpi_recv` | `mpi_collective.c:1947` | UDP receive with TCP ACK + fallback |
| `mpi_barrier_ring` | `mpi_collective.c:2501` | Ring barrier over TCP |
| `kfunc` | `kfunc.bpf.c:630` | XDP entry point; dispatches to handle_original/handle_clone |
| `handle_original` | `kfunc.bpf.c:476` | Triggers cloning on the first arrival of an MPI packet |
| `handle_clone` | `kfunc.bpf.c:178` | Rewrites and XDP_TX's each copy to its designated next hop |
| `ebpf_loader_*` | `my_ebpf.h` | BPF object open/load/attach/cleanup |

---

## Constraints and Known Limitations

- **Source IP filter** — `kfunc` only processes packets with `saddr == 192.168.101.2` (GRECALE_IP); packets from any other source are `XDP_PASS`'d without inspection.
- **Single-NIC assumption** — all ranks communicate through one network interface; `GRECALE_IP` / `MAESTRALE_IP` are hardcoded in the headers.
- **Localhost-only TCP fallback** — ACK sockets use `127.0.0.1`; TCP retransmit works only when all ranks are on the same machine.
- **Linear broadcast over-clones** — `XDP_CLONE_PASS(size)` creates one extra copy (ID=`size`) that wraps around to rank 1 or root. It is silently discarded via a failed `proc_to_address` lookup (`XDP_PASS`), but the page pool still allocates and frees that copy.
- **BPF maps must be pre-populated** — `address_to_proc` and `proc_to_address` are filled at `mpi_init` startup; late joiners are not supported.
- **Fork-based process model** — all ranks share the parent's FDs up to the fork; the BPF FD is inherited, but each child creates its own sockets independently.
- **CPU pinning** — rank `r` is pinned to CPU core `r`; systems with fewer cores than ranks will fail `sched_setaffinity`.
- **UDP unreliability** — XDP clone copies are delivered best-effort; any lost copy triggers a full TCP retransmit which is significantly slower than the XDP path.
- **No chaining from copies** — copies run `handle_clone` (not `handle_original`), so a copy can never trigger a second round of cloning.
- **Fixed output format** — timing is written as `rank,elapsed_seconds\n` per rank; cross-rank aggregation must be done externally on the CSV.
