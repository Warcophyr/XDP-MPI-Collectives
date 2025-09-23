# CLANG        := clang
# GCC          := gcc
# KFLAGS       := -O2 -g -target bpf
# UFLAGS       := -O2 -Wall
# LIBS         := -lbpf -lelf -lz -lxdp -lm

# KOBJ         := xdp_prog_kern.o
# KMAP         := xdp_map_mpi.o
# ULOADER      := xdp_loader
# MPI     	 := MPI
# KERNELMODULE := kernel_module_xdp.ko


# all: $(KOBJ) $(ULOADER) $(MPI) $(KMAP)


# $(KOBJ): xdp_prog_kern.c
# 	$(CLANG) $(KFLAGS) -c $< -o $@

# $(KMAP): xdp_map_mpi.c
# 	$(CLANG) $(KFLAGS) -c $< -o $@

# $(ULOADER): xdp_loader.c $(KOBJ)
# 	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

# $(MPI): MPI.c 
# 	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

# $(KERNELMODULE): kernel_module_xdp.c
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

obj-m += kernel_module_xdp.o
# KBUILD_CFLAGS += -g -O2
all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

load:
	sudo insmod kernel_module_xdp.ko 

unload:
	sudo rmmod kernel_module_xdp

ls: 
	sudo lsmod | grep kernel_module_xdp

clean:
# 	rm -f $(KOBJ) $(ULOADER)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
