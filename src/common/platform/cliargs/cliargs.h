#ifndef WIRED_CLIARGS_CLIARGS_H
#define WIRED_CLIARGS_CLIARGS_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * Parse already-materialized `argc`/`argv` for named flags of the form
 * `--flag value`. No libc: no `getopt`, no `strtol`, no `strcmp`.
 *
 * This module only parses argv it is handed — it does not read the kernel
 * stack itself. See cliargs.c's file comment for why raw stack extraction
 * (from `_start`) is out of scope here.
 */

/**
 * Find `flag` in argv and parse its following element as a non-negative
 * base-10 integer.
 *
 * @param argc   argument count
 * @param argv   argument vector (argv[0] is the program name, as usual)
 * @param flag   NUL-terminated flag to search for, e.g. "--port"
 * @param defval value returned when the flag is absent, dangling (no
 *               following element), or its value is not purely digits
 * @return the parsed value, or defval
 */
i64 wired_cliargs_int(int argc, char** argv, const char* flag, i64 defval);

/**
 * Find `flag` in argv and return a pointer to its following element.
 *
 * @param argc   argument count
 * @param argv   argument vector
 * @param flag   NUL-terminated flag to search for, e.g. "--cert"
 * @param defval value returned when the flag is absent or dangling
 * @return argv[i+1] where argv[i] == flag, or defval
 */
const char* wired_cliargs_str(
    int argc, char** argv, const char* flag, const char* defval);

#endif
