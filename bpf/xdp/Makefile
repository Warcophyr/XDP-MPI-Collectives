TARGET := mpi_xdp

CFLAGS := -g -O2 --target=bpf -DDEBUG=$(DEBUG)

.PHONY: all clean

all: $(TARGET).bpf.o $(TARGET)_inline.bpf.o

$(TARGET).bpf.o: $(TARGET).bpf.c
	clang $(CFLAGS) -c $< -o $@

# Same source, same logic: only the 58 bytes at the front of each copy are
# written by the NIC instead of by the program. See forward_copy().
$(TARGET)_inline.bpf.o: $(TARGET).bpf.c axdp_tx.h
	clang $(CFLAGS) -DAXDP_INLINE -c $< -o $@

clean:
	rm -f $(TARGET).bpf.o $(TARGET)_inline.bpf.o
