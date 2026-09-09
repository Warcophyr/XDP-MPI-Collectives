CLANG        := clang
GCC          := gcc
UFLAGS       := -O3 -Wall 
GDB          := -g -fsanitize=address -fno-omit-frame-pointer
LIBS         := -lbpf -lelf -lz -lxdp -lm
# Ubuntu's /usr/sbin/bpftool is a wrapper that refuses to run when there is
# no linux-tools package for the running kernel; point this at a real one.
BPFTOOL      ?= bpftool
SRC		  := ../my_ebpf.c

TARGET := mirror

all: mirror tx

mirror:
	clang -g -O2 --target=bpf -c $(TARGET).bpf.c -o $(TARGET).bpf.o -I ./kernel_module
	$(BPFTOOL) gen skeleton $(TARGET).bpf.o > $(TARGET).bpf.skel.h
	gcc -g -O2 -o $(TARGET) $(TARGET).c -lbpf


tx: ./tx.c
	$(GCC) $(UFLAGS) $(SRC) $< -o $@ $(LIBS)

clean:
	rm -f tx
	rm -f $(TARGET) $(TARGET:=.bpf.o) $(TARGET:=.bpf.skel.h)
