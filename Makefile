CLANG        := clang
GCC          := gcc
KFLAGS       := -O2 -target bpf
UFLAGS       := -O2 -Wall
LIBS         := -lbpf -lelf -lz -lxdp

KOBJ         := xdp_prog_kern.o
ULOADER      := xdp_loader
BRODCAST     := MPI_brodcast

all: $(KOBJ) $(ULOADER) $(BRODCAST)

$(KOBJ): xdp_prog_kern.c
	$(CLANG) $(KFLAGS) -c $< -o $@

$(ULOADER): xdp_loader.c $(KOBJ)
	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

$(BRODCAST): MPI_brodcast.c 
	$(GCC) $< -o $@

clean:
	rm -f $(KOBJ) $(ULOADER)
