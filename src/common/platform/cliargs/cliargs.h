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

/**
 * Find `flag` anywhere in argv, including argv's last element (unlike
 * `wired_cliargs_int`/`wired_cliargs_str`, no following value is expected).
 *
 * @param argc argument count
 * @param argv argument vector
 * @param flag NUL-terminated flag to search for, e.g. "--verbose"
 * @return 1 if flag is present in argv, 0 otherwise
 */
int wired_cliargs_flag(int argc, char** argv, const char* flag);

/**
 * Parse a dotted-decimal IPv4 address ("a.b.c.d") into 4 bytes.
 *
 * Rejects (leaving out unchanged): any octet outside 0-255, a segment
 * count other than 4, an empty segment, a non-digit character, or
 * trailing garbage after the last octet. Leading zeros are accepted.
 *
 * @param s   NUL-terminated dotted-decimal string
 * @param out 4-byte buffer receiving the parsed octets on success
 * @return 1 on success, 0 on any parse error
 */
int wired_cliargs_ipv4(const char* s, u8 out[4]);

#endif
