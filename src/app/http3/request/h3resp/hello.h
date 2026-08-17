#ifndef H3RESP_HELLO_H
#define H3RESP_HELLO_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. Build a complete minimal response stream: status 200 with the
 * body "hello\n". Returns 1 with out->len set, 0 if out lacks capacity. */
int h3resp_hello(wired_obuf* out);

#endif
