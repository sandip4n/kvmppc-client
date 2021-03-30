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
#include <signal.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/kvm.h>

#define PPC_INST_ADD			0x7c000214
#define PPC_INST_ADDI			0x38000000
#define PPC_INST_ADDIS			0x3c000000
#define PPC_INST_BRANCH			0x48000000
#define PPC_INST_NOP			0x60000000
#define PPC_INST_ORI			0x60000000
#define PPC_INST_ORIS			0x64000000

#define ___PPC_RA(a)			(((a) & 0x1f) << 16)
#define ___PPC_RB(b)			(((b) & 0x1f) << 11)
#define ___PPC_RC(c)			(((c) & 0x1f) << 6)
#define ___PPC_RS(s)			(((s) & 0x1f) << 21)
#define ___PPC_RT(t)			___PPC_RS(t)
#define ___PPC_LI(i)			(((i) & 0xffffff) << 2)
#define ___PPC_AA(i)			(((i) & 0x1) << 1)
#define ___PPC_LK(i)			((i) & 0x1)
#define ___PPC_SI(i)			((i) & 0xffff)
#define ___PPC_UI(i)			___PPC_SI(i)

#define PPC_RAW_ADD(t, a, b)		(PPC_INST_ADD | ___PPC_RT(t) | ___PPC_RA(a) | ___PPC_RB(b))
#define PPC_RAW_ADDI(d, a, i)		(PPC_INST_ADDI | ___PPC_RT(d) | ___PPC_RA(a) | ___PPC_SI(i))
#define PPC_RAW_LI(r, i)		PPC_RAW_ADDI(r, 0, i)
#define PPC_RAW_ADDIS(d, a, i)		(PPC_INST_ADDIS | ___PPC_RT(d) | ___PPC_RA(a) | ___PPC_SI(i))
#define PPC_RAW_LIS(r, i)		PPC_RAW_ADDIS(r, 0, i)
#define PPC_RAW_BRANCH(i, a, l)		(PPC_INST_BRANCH | ___PPC_LI(i) | ___PPC_AA(a) | ___PPC_LK(l))
#define PPC_RAW_NOP()			(PPC_INST_NOP)
#define PPC_RAW_ORI(d, a, i)		(PPC_INST_ORI | ___PPC_RA(d) | ___PPC_RS(a) | ___PPC_UI(i))
#define PPC_RAW_ORIS(d, a, i)		(PPC_INST_ORIS | ___PPC_RA(d) | ___PPC_RS(a) | ___PPC_UI(i))

unsigned long pgsize, vcpumsize;
struct kvm_regs vmregs;
struct kvm_run *vmrun;
int kvmfd, vcpufd;
void *vmmem;

void support_assert(bool cond, char *file, int line, char *name)
{
	if (cond) {
		fprintf(stderr, "error: %s:%d: %s is not supported\n",
			file, line, name);
		exit(EXIT_FAILURE);
	}
}

void syscall_assert(bool cond, char *file, int line, char *name)
{
	if (cond) {
		fprintf(stderr, "error: %s:%d: %s() failed: %s\n",
			file, line, name, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void kvm_show_registers(void)
{
	int ret, i;

	ret = ioctl(vcpufd, KVM_GET_REGS, &vmregs);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");

	for (i = 0; i < sizeof(vmregs.gpr) / sizeof(vmregs.gpr[0]); i++)
		printf("kvm regs gpr[%02d] = 0x%016lx\n", i, vmregs.gpr[i]);
	printf("kvm regs pc  = 0x%016lx\n", vmregs.pc);
	printf("kvm regs cr  = 0x%016lx\n", vmregs.cr);
	printf("kvm regs ctr = 0x%016lx\n", vmregs.ctr);
	printf("kvm regs lr  = 0x%016lx\n", vmregs.lr);
	printf("kvm regs xer = 0x%016lx\n", vmregs.xer);
}

void sigint_handler(int signum, siginfo_t *sinfo, void *ctx)
{
	/* FIXME unsafe to call printf from a signal handler */
	printf("program interrupted\n");
	kvm_show_registers();

	munmap(vmrun, vcpumsize);
	munmap(vmmem, pgsize);
	close(vcpufd);
	close(kvmfd);

	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	struct kvm_userspace_memory_region vmmreg;
	struct sigaction sigint_action;
	struct kvm_enable_cap kvmcap;
	struct kvm_sregs vmsregs;
	int vmfd, ret, i;

	kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	syscall_assert(kvmfd < 0, __FILE__, __LINE__, "open");

	ret = ioctl(kvmfd, KVM_GET_API_VERSION, NULL);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");
	printf("kvm version = %d\n", ret);

	ret = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");
	printf("kvm user memory capability = %s\n", ret ? "yes" : "no");
	support_assert(!ret, __FILE__, __LINE__, "KVM_CAP_USER_MEMORY");

	ret = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_PPC_PAPR);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");
	printf("kvm papr capability = %s\n", ret ? "yes" : "no");
	support_assert(!ret, __FILE__, __LINE__, "KVM_CAP_PPC_PAPR");

	vmfd = ioctl(kvmfd, KVM_CREATE_VM, KVM_VM_PPC_HV);
	syscall_assert(vmfd < 0, __FILE__, __LINE__, "ioctl");

	pgsize = sysconf(_SC_PAGESIZE);
	vmmem = mmap(NULL, pgsize, PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
	syscall_assert(vmmem == MAP_FAILED, __FILE__, __LINE__, "mmap");

	for (i = 0; i < pgsize / sizeof(unsigned int); i++)
		((unsigned int *) vmmem)[i] = PPC_RAW_NOP();

	((unsigned int *) vmmem)[0] = PPC_RAW_ORIS(13, 13, 0xdead);
	((unsigned int *) vmmem)[1] = PPC_RAW_ORI(14, 14, 0xbeef);
	((unsigned int *) vmmem)[2] = PPC_RAW_ADD(15, 13, 14);
	((unsigned int *) vmmem)[i - 1] = PPC_RAW_BRANCH(0, 0, 0);

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
	vmregs.pc = 0x10000;

	printf("kvm pvr = 0x%08x\n", vmsregs.pvr);
	printf("kvm msr = 0x%016lx\n", vmregs.msr);

	ret = ioctl(vcpufd, KVM_SET_REGS, &vmregs);
	syscall_assert(ret < 0, __FILE__, __LINE__, "ioctl");

	sigint_action.sa_handler = 0;
	sigint_action.sa_sigaction = sigint_handler;
	ret = sigprocmask(SIG_SETMASK, 0, &sigint_action.sa_mask);
	syscall_assert(ret < 0, __FILE__, __LINE__, "sigprocmask");
	sigint_action.sa_flags = SA_SIGINFO;
	sigint_action.sa_restorer = 0;
	ret = sigaction(SIGINT, &sigint_action, NULL);
	syscall_assert(ret < 0, __FILE__, __LINE__, "sigaction");

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

	kvm_show_registers();
	munmap(vmrun, vcpumsize);
	munmap(vmmem, pgsize);
	close(vcpufd);
	close(kvmfd);

	return EXIT_SUCCESS;
}
