#ifndef WIRED_SRVPIN_SRVPIN_H
#define WIRED_SRVPIN_SRVPIN_H

/** @file
 * CPU affinity / core pinning (Linux x86_64, direct sched_setaffinity(2)/
 * sched_getaffinity(2) syscalls, no libc). */

/** Count of CPUs currently allowed for this process (sched_getaffinity(2)).
 * @return the count (>= 1 on any real system), or a negative value
 * (-errno) on syscall failure. */
int wired_srvpin_cpu_count(void);

/** Pin the calling thread to exactly one CPU via sched_setaffinity(2) with an
 * 8-byte (64-bit) affinity mask covering CPUs 0-63 (bit cpu_index set, all
 * others clear).
 * @param cpu_index target CPU, must be in [0,63]
 * @return 0 on success; negative on failure (cpu_index out of [0,63], or a
 * syscall error such as the CPU not being in the process's allowed set). */
int wired_srvpin_bind_self(int cpu_index);

#endif
