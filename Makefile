CLANG        := clang
GCC          := gcc
# KFLAGS       := -O2 -g -target bpf
UFLAGS       := -O3 -Wall 
GDB          := -g -fsanitize=address -fno-omit-frame-pointer
LIBS         := -lbpf -lelf -lz -lxdp -lm
SRC		  := my_ebpf.c
# KOBJ         := xdp_prog_kern.o
# KMAP         := xdp_map_mpi.o
# ULOADER      := xdp_loader
# MPI     	 := MPI
# KERNELMODULE := kernel_module_xdp.ko
# TARGET := kfunc
MIRROR := mirror

.PHONY : all clean


# all: MPI kfunc tc xdp xsk uprobe
all: MPI tc xdp xsk mirror tx uprobe kprobe


# $(KOBJ): xdp_prog_kern.c
# 	$(CLANG) $(KFLAGS) -c $< -o $@ -I ../XDP-MPI-Collectives/kernel_module

# $(KMAP): xdp_map_mpi.c
# 	$(CLANG) $(KFLAGS) -c $< -o $@

# $(ULOADER): xdp_loader.c $(KOBJ)
# 	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

# $(MPI): MPI.c 
# 	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

MPI: ./MPI.c
# 	$(GCC) $(UFLAGS) $(GDB) $(SRC) $< -o $@ $(LIBS)
	$(GCC) $(UFLAGS) $(SRC) $< -o $@ $(LIBS)

# kfunc: 
# 	clang -g -O2 --target=bpf -c $(TARGET).bpf.c -o $(TARGET).bpf.o -I ./kernel_module -DDEBUG=$(DEBUG)
# 	bpftool gen skeleton $(TARGET).bpf.o > $(TARGET).bpf.skel.h
# 	gcc -g -O2 -o $(TARGET) $(TARGET).c -lbpf

mirror:
	make -C "mirror" mirror

tx: 
	make -C "mirror" tx
uprobe:
	clang -g -O2 --target=bpf -D__TARGET_ARCH_x86 -c profiling/uprobe.bpf.c -o profiling/uprobe.bpf.o -I ./kernel_module -DDEBUG=$(DEBUG)
	bpftool gen skeleton profiling/uprobe.bpf.o > profiling/uprobe.bpf.skel.h
	gcc -g -O2 -I profiling -o profiling/uprobe profiling/uprobe.c -lbpf

kprobe:
	clang -g -O2 --target=bpf -D__TARGET_ARCH_x86 -c profiling/kprobe.bpf.c -o kprobe.bpf.o -I ./kernel_module -DDEBUG=$(DEBUG)
	bpftool gen skeleton kprobe.bpf.o > kprobe.bpf.skel.h
	gcc -g -O2 -o kprobe profiling/kprobe.c -lbpf -lelf -lz


tc:
	make -C "bpf/tc" DEBUG=$(DEBUG)

xdp:
	make -C "bpf/xdp" DEBUG=$(DEBUG)

xsk:
	make -C "bpf/xsk" DEBUG=$(DEBUG)

ETH       ?= enp52s0f1np1
NRANKS    ?= 8
BASE_PORT ?= 5000

run:
	sudo ./MPI -n $(NRANKS) -i $(ETH)

run-xsk: setup-xsk
	sudo ./MPI -n $(NRANKS) -i $(ETH) -x

# Configure NRANKS NIC queues and add one ntuple rule per rank so that
# UDP dst-port (BASE_PORT+r) is steered to queue r.  Required before
# running ./MPI with -x (AF_XDP mode).  Must be re-run after driver reload.
setup-xsk:
	sudo ethtool -L $(ETH) combined $(NRANKS)
	sudo ethtool -K $(ETH) ntuple on
	sudo ethtool --set-rxfh-indir $(ETH) equal $(NRANKS)
	for r in $$(seq 0 $$(($(NRANKS)-1))); do \
		sudo ethtool -N $(ETH) flow-type udp4 \
			dst-port $$(($(BASE_PORT)+$$r)) action $$r; \
	done
	@echo "NIC configured: $(NRANKS) queues, ntuple rules BASE_PORT=$(BASE_PORT)"

teardown-xsk:
	-sudo ethtool -K $(ETH) ntuple off
	-sudo ethtool -L $(ETH) combined 1
	-sudo ethtool --set-rxfh-indir $(ETH) equal 1

clean:
	rm -f MPI
	make -C "mirror" clean
	make -C "bpf/tc" clean
	make -C "bpf/xdp" clean
	make -C "bpf/xsk" clean	
# 	rm -f $(KOBJ) $(ULOADER)
# 	rm -f $(TARGET) $(TARGET:=.bpf.o) $(TARGET:=.bpf.skel.h)
# 	rm -f $(MIRROR) $(MIRROR:=.bpf.o) $(MIRROR:=.bpf.skel.h)
# 	rm -f uprobe uprobe.bpf.o uprobe.bpf.skel.h
# 	rm -f kprobe kprobe.bpf.o kprobe.bpf.skel.h
