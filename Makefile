#
# The following macros affect compilation:
#
#   -DRELEASE       remove a lot of debug strings.
#
# Set corresponding environment variable to 1 do define them.
#

HV_MACROS :=
ifeq ($(RELEASE),1)
	HV_MACROS += -DRELEASE
endif

GIT_VERSION := $(shell	 						\
	if [ "x$(src)" != "x" ]; then				\
		git -C $(src) describe --always --tags;	\
	fi)
ccflags-y := -I$(src)/include -DVERSION=\"$(GIT_VERSION)\" $(HV_MACROS)
ldflags-y := -T$(src)/scripts/cappsule.lds -L$(src)
obj-m := cappsule.o cappsule-guest.o

cappsule-objs :=			\
	common/bluepill.o		\
	common/channel.o		\
	common/exec_policy.o	\
	common/log.o			\
	common/time.o			\
	common/xchan.o			\
	host/asm.o				\
	host/breakpoint.o		\
	host/capsule.o			\
	host/ept.o				\
	host/interrupt.o		\
	host/memory.o			\
	host/process.o			\
	host/snapshot.o			\
	host/symbols.o			\
	host/time.o				\
	host/transition.o		\
	host/vm_exit.o			\
	host/vmcs.o				\
	host/vmx_instr.o		\
	host/xchan.o			\
	trusted/asm.o			\
	trusted/cappsule.o		\
	trusted/channel.o		\
	trusted/create_capsule.o\
	trusted/exec_policy.o	\
	trusted/fingerprint.o	\
	trusted/mfn.o			\
	trusted/vmm.o			\
	trusted/shadowp.o		\
	trusted/time.o			\
	trusted/xchan.o

cappsule-guest-objs :=		\
	common/channel.o		\
	guest/asm.o				\
	guest/console.o			\
	guest/exec.o			\
	guest/init.o			\
	guest/mfn.o				\
	guest/schedule.o		\
	guest/shared_mem.o		\
	guest/symbols.o			\
	guest/timers.o			\
	guest/workqueue.o		\
	guest/xchan.o			\

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
