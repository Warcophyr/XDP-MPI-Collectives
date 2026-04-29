TARGET := mpi_tc

all:
	clang -g -O2 --target=bpf -c $(TARGET).bpf.c -o $(TARGET).bpf.o -DDEBUG=$(DEBUG)
# 	bpftool gen skeleton $(TARGET).bpf.o > $(TARGET).bpf.skel.h
# 	gcc -g -O2 -o $(TARGET) $(TARGET).c -lbpf

clean:
	rm -f $(TARGET).bpf.o $(TARGET).bpf.skel.h $(TARGET)