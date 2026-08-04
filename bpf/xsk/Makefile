TARGET := mpi_xsk

all:
	clang -g -O2 --target=bpf -c $(TARGET).bpf.c -o $(TARGET).bpf.o -DDEBUG=$(DEBUG)

clean:
	rm -f $(TARGET).bpf.o
