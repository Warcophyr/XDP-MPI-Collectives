CLANG        := clang
GCC          := gcc
KFLAGS       := -O2 -target bpf
UFLAGS       := -O2 -Wall
LIBS         := -lbpf -lelf -lz -lxdp

KOBJ         := xdp_prog_kern.o
ULOADER      := xdp_loader

all: $(KOBJ) $(ULOADER)

$(KOBJ): xdp_prog_kern.c
	$(CLANG) $(KFLAGS) -c $< -o $@

$(ULOADER): xdp_loader.c $(KOBJ)
	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f $(KOBJ) $(ULOADER)
