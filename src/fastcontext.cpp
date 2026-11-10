// x86Sim: getcontext()/setcontext() for darlingserver's microthreads without the signal mask.
//
// glibc's getcontext() and setcontext() each make an rt_sigprocmask syscall (to save and to restore the mask). Every
// RPC switches microthread contexts about four times (Thread::doWork: getcontext of the thread top and of the new
// context, setcontext into it, setcontext back), so while scrolling darlingserver made ~110,000 rt_sigprocmask calls
// a second, a third of all its syscalls. darlingserver never changes its signal mask, so these save and restore only
// the registers, the x87 environment and MXCSR, exactly like glibc otherwise (same ucontext_t layout, so glibc's
// makecontext() still works on them; offsets checked below).
#include <stddef.h>
#include <ucontext.h>

#define GREG(r) (offsetof(ucontext_t, uc_mcontext.gregs) + 8 * (r))
static_assert(GREG(REG_R8) == 40 && GREG(REG_R9) == 48 && GREG(REG_R12) == 72 && GREG(REG_R13) == 80 &&
	GREG(REG_R14) == 88 && GREG(REG_R15) == 96 && GREG(REG_RDI) == 104 && GREG(REG_RSI) == 112 &&
	GREG(REG_RBP) == 120 && GREG(REG_RBX) == 128 && GREG(REG_RDX) == 136 && GREG(REG_RCX) == 152 &&
	GREG(REG_RSP) == 160 && GREG(REG_RIP) == 168, "ucontext_t gregs layout");
static_assert(offsetof(ucontext_t, uc_mcontext.fpregs) == 224, "ucontext_t fpregs pointer");
static_assert(offsetof(ucontext_t, __fpregs_mem) == 424, "ucontext_t __fpregs_mem");
static_assert(offsetof(ucontext_t, __fpregs_mem) + offsetof(struct _libc_fpstate, mxcsr) == 448, "ucontext_t mxcsr");

__asm__(
	".text\n"
	".globl dserver_getcontext\n"
	".type dserver_getcontext, @function\n"
	"dserver_getcontext:\n"
	"	movq %rbx, 128(%rdi)\n"
	"	movq %rbp, 120(%rdi)\n"
	"	movq %r12, 72(%rdi)\n"
	"	movq %r13, 80(%rdi)\n"
	"	movq %r14, 88(%rdi)\n"
	"	movq %r15, 96(%rdi)\n"
	"	movq %rdi, 104(%rdi)\n"
	"	movq %rsi, 112(%rdi)\n"
	"	movq %rdx, 136(%rdi)\n"
	"	movq %rcx, 152(%rdi)\n"
	"	movq %r8, 40(%rdi)\n"
	"	movq %r9, 48(%rdi)\n"
	"	movq (%rsp), %rcx\n"        // return address: where setcontext() resumes
	"	movq %rcx, 168(%rdi)\n"
	"	leaq 8(%rsp), %rcx\n"       // the caller's stack pointer after the return
	"	movq %rcx, 160(%rdi)\n"
	"	leaq 424(%rdi), %rcx\n"     // uc_mcontext.fpregs = &__fpregs_mem, as glibc does
	"	movq %rcx, 224(%rdi)\n"
	// x86Sim (Speed 32): only the x87 control word. These switches happen at call boundaries, where the ABI leaves the
	// x87 stack empty and the status word holds nothing a callee relies on; fnstenv + fldenv (serializing, ~10% of
	// darlingserver's own time per RPC) saved and reloaded the whole environment
	"	fnstcw (%rcx)\n"
	"	stmxcsr 448(%rdi)\n"
	"	xorl %eax, %eax\n"
	"	ret\n"
	".size dserver_getcontext, .-dserver_getcontext\n"

	".globl dserver_setcontext\n"
	".type dserver_setcontext, @function\n"
	"dserver_setcontext:\n"
	"	movq %rdi, %rdx\n"
	"	movq 224(%rdx), %rcx\n"
	"	fldcw (%rcx)\n"
	"	ldmxcsr 448(%rdx)\n"
	"	movq 160(%rdx), %rsp\n"
	"	movq 128(%rdx), %rbx\n"
	"	movq 120(%rdx), %rbp\n"
	"	movq 72(%rdx), %r12\n"
	"	movq 80(%rdx), %r13\n"
	"	movq 88(%rdx), %r14\n"
	"	movq 96(%rdx), %r15\n"
	"	movq 168(%rdx), %rcx\n"
	"	pushq %rcx\n"               // ret below jumps to rip with rsp as saved (or as makecontext() set it up)
	"	movq 104(%rdx), %rdi\n"
	"	movq 112(%rdx), %rsi\n"
	"	movq 152(%rdx), %rcx\n"
	"	movq 40(%rdx), %r8\n"
	"	movq 48(%rdx), %r9\n"
	"	movq 136(%rdx), %rdx\n"
	"	xorl %eax, %eax\n"
	"	ret\n"
	".size dserver_setcontext, .-dserver_setcontext\n"
);
