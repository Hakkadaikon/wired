#include "common/platform/thread/thread.h"

/* Stack geometry: one guard page below a 1 MiB stack. */
#define THREAD_STACK_LEN 1048576
#define THREAD_GUARD_LEN 4096
#define THREAD_MAP_LEN (THREAD_GUARD_LEN + THREAD_STACK_LEN)

/* mmap/mprotect constants, Linux x86_64 <asm-generic/mman-common.h>. */
#define THREAD_PROT_NONE 0x0
#define THREAD_PROT_READ 0x1
#define THREAD_PROT_WRITE 0x2
#define THREAD_MAP_PRIVATE 0x02
#define THREAD_MAP_ANONYMOUS 0x20

/* clone(2) flags, Linux <linux/sched.h>: CLONE_VM 0x100 | CLONE_FS 0x200 |
 * CLONE_FILES 0x400 | CLONE_SIGHAND 0x800 | CLONE_THREAD 0x10000 |
 * CLONE_SYSVSEM 0x40000 | CLONE_PARENT_SETTID 0x100000 |
 * CLONE_CHILD_CLEARTID 0x200000. PARENT_SETTID makes the KERNEL store the
 * tid into t->tid, so no user-space store can race a fast-exiting child's
 * CLEARTID clear; CHILD_CLEARTID zeroes t->tid on exit and wakes the join
 * futex. */
#define THREAD_CLONE_FLAGS \
  (0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000 | 0x100000 | 0x200000)

/* FUTEX_WAIT, Linux <linux/futex.h>. */
#define THREAD_FUTEX_WAIT 0

/* Raw clone(2). The child returns on a NEW stack, so this cannot go through
 * the C syscall6 wrapper (compiler spills would read the parent's frame).
 * SysV args: rdi=flags, rsi=child_stack, rdx=parent_tid, rcx=child_tid,
 * r8=tls; the syscall ABI wants arg4 in r10. Parent path: return the
 * kernel's rax (tid or -errno). Child path (rax==0): pop fn and arg pushed
 * by thread_stack_prep, align rsp so `call` leaves RSP%16==8 at fn entry
 * (x86_64 ABI, same discipline as the examples' _start), call fn, then
 * SYS_exit(0) which fires the CLEARTID clear+wake. */
i64 wired_thread_clone_raw(
    i64 flags, u8* child_stack, i32* parent_tid, i32* child_tid, i64 tls);
__asm__(
    ".text\n"
    ".globl wired_thread_clone_raw\n"
    "wired_thread_clone_raw:\n"
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

/* Map guard+stack and turn the low page into the guard. mmap failures are
 * -errno in -4095..-1 (kernel guarantee), and x86_64 user addresses are
 * never negative, so `< 0` is the error test. */
static i64 thread_map_stack(wired_thread* t) {
  i64 base = syscall6(
      SYS_mmap, 0, THREAD_MAP_LEN, THREAD_PROT_READ | THREAD_PROT_WRITE,
      THREAD_MAP_PRIVATE | THREAD_MAP_ANONYMOUS, -1, 0);
  if (base < 0) return base;
  i64 r = syscall3(SYS_mprotect, base, THREAD_GUARD_LEN, THREAD_PROT_NONE);
  if (r < 0) {
    syscall3(SYS_munmap, base, THREAD_MAP_LEN, 0);
    return r;
  }
  t->stack     = (u8*)base;
  t->stack_len = THREAD_MAP_LEN;
  return 0;
}

/* Seed the child stack: fn then arg at the top-16 slot (mmap is page
 * aligned, so the returned stack pointer stays 16-byte aligned for the
 * child's pops in wired_thread_clone_raw). */
static u8* thread_stack_prep(wired_thread* t, void (*fn)(void*), void* arg) {
  u64* slots = (u64*)(t->stack + t->stack_len - 16);
  slots[0]   = (u64)fn;
  slots[1]   = (u64)arg;
  return (u8*)slots;
}

i64 wired_thread_start(wired_thread* t, void (*fn)(void*), void* arg) {
  i64 r = thread_map_stack(t);
  if (r < 0) return r;
  r = wired_thread_clone_raw(
      THREAD_CLONE_FLAGS, thread_stack_prep(t, fn, arg), &t->tid, &t->tid, 0);
  if (r < 0) {
    syscall3(SYS_munmap, t->stack, t->stack_len, 0);
    t->stack = 0;
    return r;
  }
  return 0;
}

/* Join protocol: ACQUIRE-load the tid word (happens-before edge from the
 * kernel's CLEARTID store); 0 means exited, otherwise FUTEX_WAIT with the
 * just-loaded value as expected. Any futex return (wake, EAGAIN, EINTR)
 * goes back to the load. */
static void thread_wait_tid(i32* tid) {
  i32 v;
  while ((v = __atomic_load_n(tid, __ATOMIC_ACQUIRE)) != 0)
    syscall6(SYS_futex, (i64)tid, THREAD_FUTEX_WAIT, v, 0, 0, 0);
}

i64 wired_thread_join(wired_thread* t) {
  thread_wait_tid(&t->tid);
  syscall3(SYS_munmap, t->stack, t->stack_len, 0);
  t->stack     = 0;
  t->stack_len = 0;
  return 0;
}

i64 wired_thread_tid(void) { return syscall1(SYS_gettid, 0); }
