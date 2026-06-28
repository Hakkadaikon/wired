#ifndef QUIC_H3RESP_HELLO_H
#define QUIC_H3RESP_HELLO_H

#include "sys/syscall.h"

/* RFC 9114 4.1. Build a complete minimal response stream: status 200 with the
 * body "hello\n". Returns 1 with *out_len set, 0 if out lacks capacity. */
int quic_h3resp_hello(u8 *out, usz cap, usz *out_len);

#endif
