#ifndef __powerpc64__
#error "unsupported architecture"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/kvm.h>

void syscall_assert(bool cond, char *file, int line, char *name)
{
	if (cond) {
		fprintf(stderr, "%s:%d: %s() failed: %s\n", file, line, name,
			strerror(errno));
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	struct kvm_userspace_memory_region vmmreg;
	int kvmfd, vmfd, vcpufd, ret, i;
	unsigned long pgsize, vcpumsize;
	struct kvm_enable_cap kvmcap;
	struct kvm_sregs vmsregs;
	struct kvm_regs vmregs;
	struct kvm_run *vmrun;
	void *vmmem;

	kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	syscall_assert(kvmfd < 0, __FILE__, __LINE__, "open");

	ret = ioctl(kvmfd, KVM_GET_API_VERSION, NULL);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");
	printf("kvm version = %d\n", ret);

	ret = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");
	printf("kvm user memory capability = %s\n", ret ? "yes" : "no");

	ret = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_PPC_PAPR);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");
	printf("kvm papr capability = %s\n", ret ? "yes" : "no");

	vmfd = ioctl(kvmfd, KVM_CREATE_VM, KVM_VM_PPC_HV);
	syscall_assert(vmfd < 0, __FILE__, __LINE__, "ioctl");

	pgsize = sysconf(_SC_PAGESIZE);
	vmmem = mmap(NULL, pgsize, PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
	syscall_assert(vmmem == MAP_FAILED, __FILE__, __LINE__, "mmap");

	for (i = 0; i < pgsize / sizeof(unsigned int); i++)
		((unsigned int *) vmmem)[i] = 0x60000000; /* nop */
	((unsigned int *) vmmem)[i - 1] = 0x48000000;     /* b . */

	memset(&vmmreg, 0, sizeof(struct kvm_userspace_memory_region));
	vmmreg.slot = 0;
	vmmreg.guest_phys_addr = 0x10000;
	vmmreg.memory_size = pgsize;
	vmmreg.userspace_addr = (unsigned long) vmmem;
	vmmreg.flags = 0;

	ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &vmmreg);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");

	vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0UL);
	syscall_assert(vcpufd < 0, __FILE__, __LINE__, "ioctl");

	ret = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");

	vcpumsize = ret;
	vmrun = mmap(NULL, vcpumsize, PROT_READ | PROT_WRITE, MAP_SHARED,
		     vcpufd, 0);
	syscall_assert(vmrun == MAP_FAILED, __FILE__, __LINE__, "map");

	memset(&kvmcap, 0, sizeof(kvmcap));
	kvmcap.cap = KVM_CAP_PPC_PAPR;
	ret = ioctl(vcpufd, KVM_ENABLE_CAP, &kvmcap);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");

 	ret = ioctl(vcpufd, KVM_GET_SREGS, &vmsregs);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");

	memset(&vmregs, 0, sizeof(struct kvm_regs));
	ret = ioctl(vcpufd, KVM_GET_REGS, &vmregs);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");

	memset(&vmregs, 0, sizeof(struct kvm_regs));
	vmregs.msr = (1UL << 63) | (1UL << 0); /* sf, le only */
	vmregs.gpr[14] = 0xdead;
	vmregs.gpr[15] = 0xbeef;
	vmregs.gpr[16] = 0x0;
	vmregs.pc = 0x10000;

	printf("kvm pvr = 0x%08x\n", vmsregs.pvr);
	printf("kvm msr = 0x%016lx\n", vmregs.msr);

	ret = ioctl(vcpufd, KVM_SET_REGS, &vmregs);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");

	do {
		ret = ioctl(vcpufd, KVM_RUN, NULL);

		switch (vmrun->exit_reason) {
		case KVM_EXIT_HLT:
			printf("kvm exited with KVM_EXIT_HLT\n");
			break;
		case KVM_EXIT_FAIL_ENTRY:
			printf("kvm exited with KVM_EXIT_FAIL_ENTRY\n"
			       "hardware-entry-failure-reason = 0x%lx\n",
			       vmrun->fail_entry.hardware_entry_failure_reason);
			break;
		case KVM_EXIT_INTERNAL_ERROR:
			printf("kvm exited with KVM_EXIT_INTERNAL_ERROR\n"
			       "suberror = 0x%x, ndata = %u\n",
			       vmrun->internal.suberror, vmrun->internal.ndata);
			break;
		case KVM_EXIT_INTR:
			printf("kvm exited with KVM_EXIT_INTR\n");
			break;
		default:
			printf("kvm exited with code %d\n", vmrun->exit_reason);
		}

		if (ret == -1 && errno == EINTR) {
			break;
		}
	} while (true);

	ret = ioctl(vcpufd, KVM_GET_REGS, &vmregs);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");

	printf("kvm regs gpr[14] = 0x%016lx\n", vmregs.gpr[14]);
	printf("kvm regs gpr[15] = 0x%016lx\n", vmregs.gpr[15]);
	printf("kvm regs gpr[16] = 0x%016lx\n", vmregs.gpr[16]);
	printf("kvm regs pc = 0x%016lx\n", vmregs.pc);

	munmap(vmrun, vcpumsize);
	munmap(vmmem, pgsize);
	close(vcpufd);
	close(kvmfd);

	return EXIT_SUCCESS;
}
