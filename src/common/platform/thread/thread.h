#ifndef QUIC_THREAD_H
#define QUIC_THREAD_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * Freestanding thread runtime over raw clone(2)/futex(2). No libc.
 *
 * Each thread runs on its own mmap'd stack with a PROT_NONE guard page at
 * the low end. The handle's tid word doubles as the join futex: the thread
 * is created with CLONE_CHILD_CLEARTID, so the kernel zeroes the word on
 * thread exit and wakes any futex waiter (Linux clone(2)).
 */

/**
 * One spawned thread: its kernel tid word (also the join futex) and the
 * mmap'd stack region.
 *
 * The tid word only ever moves from the kernel-set tid to 0 (monotonic
 * 1->0); reusing a wired_thread before wired_thread_join has returned is
 * undefined behavior.
 */
typedef struct {
  /** kernel tid; the kernel zeroes it on thread exit (CLONE_CHILD_CLEARTID)
   * and wakes the join futex */
  i32 tid;
  /** mmap'd stack region base (guard page first) */
  u8* stack;
  /** total mapped length including the guard page */
  usz stack_len;
} wired_thread;

/**
 * Start a thread running fn(arg) on a freshly mmap'd 1 MiB stack (plus a
 * PROT_NONE guard page below it). The kernel stores the child tid into
 * t->tid (CLONE_PARENT_SETTID) before clone returns, so the caller never
 * races the child's exit-time CLEARTID clear.
 *
 * @param t   thread handle to initialize; must stay live until join returns
 * @param fn  thread entry point; must not call libc (raw clone, no TLS)
 * @param arg opaque pointer passed to fn
 * @return 0 on success; a negative -errno when mmap/mprotect/clone fails
 *         (any partially mapped stack is unmapped first)
 */
i64 wired_thread_start(wired_thread* t, void (*fn)(void*), void* arg);

/**
 * Wait until t's thread has exited, then unmap its stack and clear the
 * handle. Blocks on the tid futex; the kernel's CLONE_CHILD_CLEARTID store
 * wakes it when the thread exits.
 *
 * @param t handle previously initialized by a successful wired_thread_start
 * @return 0 (the futex loop exits only once the tid word reads 0)
 */
i64 wired_thread_join(wired_thread* t);

/**
 * The calling thread's kernel thread id.
 *
 * @return the tid from gettid(2), always positive
 */
i64 wired_thread_tid(void);

#endif
