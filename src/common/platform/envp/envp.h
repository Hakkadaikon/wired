#ifndef WIRED_ENVP_ENVP_H
#define WIRED_ENVP_ENVP_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * Read environment variables without libc. `wired_main` receives only
 * `argc`/`argv`, but a freestanding `_start` passes the kernel's initial
 * stack through unchanged, so per the Linux ABI the NULL-terminated
 * environ block sits right after argv: `argv + argc + 1`.
 */

/**
 * Look up `name` in the environ block following argv.
 *
 * @param argc argument count
 * @param argv argument vector; argv[argc] is NULL and the environ block
 *             ("NAME=value" strings, NULL-terminated) follows it
 * @param name NUL-terminated variable name without '=', e.g. "PROTOCOLS"
 * @return pointer to the NUL-terminated value (just past '='), which is
 *         the empty string for "NAME="; 0 when name is not present
 */
const char* wired_envp_get(int argc, char** argv, const char* name);

#endif
