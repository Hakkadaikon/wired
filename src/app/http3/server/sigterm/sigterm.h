#ifndef WIRED_SIGTERM_SIGTERM_H
#define WIRED_SIGTERM_SIGTERM_H

#include "common/platform/sys/syscall.h"

/** @file
 * Freestanding SIGTERM registration (x86_64 Linux, direct rt_sigaction(2)).
 * No libc: the kernel ABI requires SA_RESTORER plus a userspace trampoline
 * that issues rt_sigreturn(2) when the handler returns, which this file
 * supplies so glibc's usual hidden `restore_rt` is not needed. */

/** Install `handler` for SIGTERM. The handler runs on the same stack at an
 * arbitrary point in the main loop, so it must do only async-signal-safe work
 * (setting a `volatile sig_atomic_t`-equivalent flag is the intended use;
 * this SDK has no signal-safety story beyond that).
 * @param handler called with the signal number on SIGTERM delivery
 * @return 1 on success, 0 if the kernel rejected registration. */
int wired_sigterm_install(void (*handler)(int));

/** Install `handler` for SIGHUP (RFC-agnostic Unix convention: the reload
 * signal), same registration mechanism and async-signal-safety rule as
 * wired_sigterm_install.
 * @param handler called with the signal number on SIGHUP delivery
 * @return 1 on success, 0 if the kernel rejected registration. */
int wired_sighup_install(void (*handler)(int));

/** Block SIGTERM and SIGHUP for the calling thread (rt_sigprocmask(2)).
 * Intended multi-worker order: the control thread blocks, then clone(2)s
 * workers (which inherit the mask), then unblocks — so shutdown signals are
 * only ever delivered to the control thread.
 * @return 1 on success, 0 if the kernel rejected the mask change. */
int wired_sigmask_block_shutdown(void);

/** Unblock SIGTERM and SIGHUP for the calling thread (rt_sigprocmask(2)),
 * the counterpart of wired_sigmask_block_shutdown. Any signal that arrived
 * while blocked is delivered before this returns.
 * @return 1 on success, 0 if the kernel rejected the mask change. */
int wired_sigmask_unblock_shutdown(void);

#endif
