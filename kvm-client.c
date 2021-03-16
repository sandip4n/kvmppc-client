#ifndef __powerpc64__
#error "unsupported architecture"
#endif

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

int main(int argc, char **argv)
{
	struct kvm_userspace_memory_region vmmreg;
	int kvmfd, vmfd, vcpufd, ret, i;
	unsigned long pgsize, vcpumsize;
	struct kvm_sregs vmsregs;
	struct kvm_regs vmregs;
	struct kvm_run *vmrun;
	void *vmmem;

	kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvmfd < 0) {
		fprintf(stderr, "%s:%d: open() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
		return EXIT_FAILURE;
	}

	ret = ioctl(kvmfd, KVM_GET_API_VERSION, NULL);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}
	printf("kvm version = %d\n", ret);

	ret = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}
	printf("kvm user memory capability = %s\n", ret ? "yes" : "no");

	vmfd = ioctl(kvmfd, KVM_CREATE_VM, KVM_VM_PPC_HV);
	if (vmfd < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

	pgsize = sysconf(_SC_PAGESIZE);
	vmmem = mmap(NULL, pgsize, PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (vmmem < 0) {
		fprintf(stderr, "%s:%d: mmap() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

	for (i = 0; i < pgsize / sizeof(unsigned int); i++)
		((unsigned int *) vmmem)[i] = 0x60000000;

	((unsigned int *) vmmem)[0] = 0x48000000;	/* b	0x0 */

	memset(&vmmreg, 0, sizeof(struct kvm_userspace_memory_region));
	vmmreg.slot = 0;
	vmmreg.guest_phys_addr = 0x0;
	vmmreg.memory_size = pgsize;
	vmmreg.userspace_addr = (unsigned long) vmmem;
	vmmreg.flags = 0;

	ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &vmmreg);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

	vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0UL);
	if (vcpufd < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

	ret = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

	vcpumsize = ret;
	vmrun = mmap(NULL, vcpumsize, PROT_READ | PROT_WRITE, MAP_SHARED,
		     vcpufd, 0);
	if (vmmem < 0) {
		fprintf(stderr, "%s:%d: mmap() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

 	ret = ioctl(vcpufd, KVM_GET_SREGS, &vmsregs);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

	ret = ioctl(vcpufd, KVM_GET_REGS, &vmregs);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

	memset(&vmregs, 0, sizeof(struct kvm_regs));
	vmregs.msr = (1UL << 63) | (1UL << 60) | (1UL << 0);
	vmregs.gpr[14] = 0xdead;
	vmregs.gpr[15] = 0xbeef;
	vmregs.gpr[16] = 0x0;
	vmregs.pc = 0x0;

	printf("kvm pvr = 0x%08x\n", vmsregs.pvr);
	printf("kvm msr = 0x%016lx\n", vmregs.msr);

	ret = ioctl(vcpufd, KVM_SET_REGS, &vmregs);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

	do {
		ret = ioctl(vcpufd, KVM_RUN, NULL);
		if (ret < 0)
			fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
				__FILE__, __LINE__, strerror(errno));
	} while (ret == -1 && errno == EINTR);

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
		default:
			printf("kvm exited with code %d\n", vmrun->exit_reason);
	}

	ret = ioctl(vcpufd, KVM_GET_REGS, &vmregs);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: ioctl() failed: %s\n",
			__FILE__, __LINE__, strerror(errno));
	}

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
