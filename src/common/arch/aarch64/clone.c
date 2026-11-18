#if defined(__aarch64__)
#include "common/arch/arch.h"

/* Raw clone(2) on a new stack (see x8664/clone.c for why it is assembly).
 * C args: x0=flags, x1=child_stack, x2=parent_tid, x3=child_tid, x4=tls;
 * arm64's clone takes (flags, stack, parent_tid, tls, child_tid), so x3
 * and x4 swap. Parent: return x0 (tid or -errno). Child (x0==0): load fn
 * and arg from the two slots at the (16-byte aligned) new sp, call fn(arg),
 * then SYS_exit(0), which fires the CLEARTID clear+wake. */
__asm__(
    ".text\n"
    ".globl wired_arch_clone_raw\n"
    "wired_arch_clone_raw:\n"
    "  mov x5, x3\n"
    "  mov x3, x4\n"
    "  mov x4, x5\n"
    "  mov x8, #220\n" /* SYS_clone */
    "  svc #0\n"
    "  cbnz x0, 1f\n"
    "  ldp x9, x0, [sp]\n" /* fn, arg */
    "  mov x29, #0\n"
    "  mov x30, #0\n"
    "  blr x9\n"
    "  mov x0, #0\n"
    "  mov x8, #93\n" /* SYS_exit */
    "  svc #0\n"
    "1:\n"
    "  ret\n");
#endif
