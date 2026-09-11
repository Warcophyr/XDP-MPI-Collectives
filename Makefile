CLANG        := clang
GCC          := gcc
# KFLAGS       := -O2 -g -target bpf
UFLAGS       := -O3 -Wall 
GDB          := -g -fsanitize=address -fno-omit-frame-pointer
LIBS         := -lbpf -lelf -lz -lxdp -lm
SRC		  := my_ebpf.c

.PHONY : all clean


# all: MPI kfunc tc xdp uprobe
all: MPI tc xdp mirror tx uprobe kprobe


# mpi_collective.c and the headers are compiled straight into this, so they
# have to be prerequisites: without them an edit there leaves the old binary in
# place and `make MPI` reports success, which is how a benchmark ends up run
# against code that was never built.
MPI: ./MPI.c $(SRC) mpi_collective.c mpi_collective.h mpi_struct.h \
     mpi_global_variable.h my_ebpf.h packet.h hton.h Wtime.h
# 	$(GCC) $(UFLAGS) $(GDB) $(SRC) $< -o $@ $(LIBS)
	$(GCC) $(UFLAGS) $(SRC) $< -o $@ $(LIBS)


mirror:
	make -C "mirror" mirror

tx: 
	make -C "mirror" tx

uprobe:
	make -C "profiling" uprobe

kprobe:
	make -C "profiling" kprobe


tc:
	make -C "bpf/tc" DEBUG=$(DEBUG)

xdp:
	make -C "bpf/xdp" DEBUG=$(DEBUG)

ETH       ?= enp52s0f1np1
NRANKS    ?= 8
BASE_PORT ?= 5000

run:
	sudo ./MPI -n $(NRANKS) -i $(ETH)

clean:
	rm -f MPI
	make -C "mirror" clean
	make -C "bpf/tc" clean
	make -C "bpf/xdp" clean
	make -C "profiling" clean	
