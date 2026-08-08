CLANG        := clang
GCC          := gcc
# KFLAGS       := -O2 -g -target bpf
UFLAGS       := -O3 -Wall 
GDB          := -g -fsanitize=address -fno-omit-frame-pointer
LIBS         := -lbpf -lelf -lz -lxdp -lm
SRC		  := my_ebpf.c

.PHONY : all clean


# all: MPI kfunc tc xdp xsk uprobe
all: MPI tc xdp xsk mirror tx uprobe kprobe


MPI: ./MPI.c
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
	make -C "profiling" clean	
