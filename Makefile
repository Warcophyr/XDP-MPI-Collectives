CLANG        := clang
GCC          := gcc
KFLAGS       := -O2 -g -target bpf
UFLAGS       := -O2 -Wall
LIBS         := -lbpf -lelf -lz -lxdp -lm

KOBJ         := xdp_prog_kern.o
KMAP         := xdp_map_mpi.o
ULOADER      := xdp_loader
MPI     	 := MPI

all: $(KOBJ) $(ULOADER) $(MPI) $(KMAP)


$(KOBJ): xdp_prog_kern.c
	$(CLANG) $(KFLAGS) -c $< -o $@

$(KMAP): xdp_map_mpi.c
	$(CLANG) $(KFLAGS) -c $< -o $@

$(ULOADER): xdp_loader.c $(KOBJ)
	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

$(MPI): MPI.c 
	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f $(KOBJ) $(ULOADER)
