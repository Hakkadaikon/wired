#include "common/platform/sys/syscall.h"

/* Freestanding entry point. No libc, no crt. */
void _start(void) {
  syscall1(SYS_exit, 0);
  __builtin_unreachable();
}
