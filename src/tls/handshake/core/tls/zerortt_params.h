#ifndef TLS_ZERORTT_PARAMS_H
#define TLS_ZERORTT_PARAMS_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 4.6.2: a client storing 0-RTT transport parameters must not use
 * 0-RTT if the server's new value lowers a limit below the remembered value.
 * Returns 1 if current is compatible (current >= remembered), 0 otherwise. */
int zerortt_param_ok(u64 remembered, u64 current);

#endif
