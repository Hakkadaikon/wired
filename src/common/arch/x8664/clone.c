#include "common/arch/arch.h"

/* Raw clone(2). The child returns on a NEW stack, so this cannot go through
 * the C syscall6 wrapper (compiler spills would read the parent's frame).
 * SysV args: rdi=flags, rsi=child_stack, rdx=parent_tid, rcx=child_tid,
 * r8=tls; the syscall ABI wants arg4 in r10. Parent path: return the
 * kernel's rax (tid or -errno). Child path (rax==0): pop fn and arg pushed
 * by the caller onto the child stack, align rsp so `call` leaves RSP%16==8
 * at fn entry (x86_64 ABI, same discipline as the examples' _start), call
 * fn, then SYS_exit(0) which fires the CLEARTID clear+wake. */
__asm__(
    ".text\n"
    ".globl wired_arch_clone_raw\n"
    "wired_arch_clone_raw:\n"
    "  movq %rcx, %r10\n"
    "  movl $56, %eax\n" /* SYS_clone */
    "  syscall\n"
    "  testq %rax, %rax\n"
    "  jnz 1f\n"
    "  popq %rax\n" /* fn */
    "  popq %rdi\n" /* arg */
    "  xorl %ebp, %ebp\n"
    "  andq $-16, %rsp\n"
    "  callq *%rax\n"
    "  xorl %edi, %edi\n"
    "  movl $60, %eax\n" /* SYS_exit */
    "  syscall\n"
    "1:\n"
    "  retq\n");
