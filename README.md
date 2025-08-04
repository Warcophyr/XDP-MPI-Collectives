# XDP-MPI-Collective
 - xdp_loader.c is a simple loader for ebpf program with
 - xdp_prog_kern.c is a simple program to test xdp program 
 
 use case: 
   - sudo ./xdp_loader xdp_prog_kern.o <<_iterface_>>

for make a xdp programm ed test with easy

- MPI.c the main program where the process are create and the ebpf program are loaded with his map
- mpi_collective.c is where al the mpi action are implement

use case:
 - sudo ./MPI -n <_number of process_>

## comandi da ricordare
- sudo cat /sys/kernel/debug/tracing/trace_pipe  (to se the bpf_printk at xdp level)
- xdp-loader status
- xdp-loader unload -a lo
