#ifndef WIRED_EXIT_EXIT_H
#define WIRED_EXIT_EXIT_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * Process termination, separate from common/platform/debug (which owns log
 * output only). wired_die composes "log a diagnostic" with "terminate the
 * process" into one action; that composite responsibility does not belong in
 * debug's MECE slice, so it gets its own domain here.
 */

/**
 * Log msg then terminate the process with exit code 1. Never returns.
 *
 * @param msg NUL-terminated diagnostic to log before exiting
 */
__attribute__((noreturn)) void wired_die(const char* msg);

#endif
