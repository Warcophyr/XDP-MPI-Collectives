TARGET1 := uprobe
TARGET2 := kprobe


all: uprobe kprobe

uprobe:
	clang -g -O2 --target=bpf -D__TARGET_ARCH_x86 -c $(TARGET1).bpf.c -o $(TARGET1).bpf.o -I ./kernel_module -DDEBUG=$(DEBUG)
	bpftool gen skeleton $(TARGET1).bpf.o > $(TARGET1).bpf.skel.h
	gcc -g -O2 -I profiling -o $(TARGET1) $(TARGET1).c -lbpf

kprobe:
	clang -g -O2 --target=bpf -D__TARGET_ARCH_x86 -c $(TARGET2).bpf.c -o $(TARGET2).bpf.o -I ./kernel_module -DDEBUG=$(DEBUG)
	bpftool gen skeleton $(TARGET2).bpf.o > $(TARGET2).bpf.skel.h
	gcc -g -O2 -o $(TARGET2) $(TARGET2).c -lbpf -lelf -lz

clean:
	rm -f $(TARGET1) $(TARGET1:=.bpf.o) $(TARGET1:=.bpf.skel.h)
	rm -f $(TARGET2) $(TARGET2:=.bpf.o) $(TARGET2:=.bpf.skel.h)