#ifndef SFLIGHT_FINISHED_BUILD_H
#define SFLIGHT_FINISHED_BUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4.4: build the server Finished message (type 0x14) under
 * suite's hash. Computes verify_data = HMAC(HKDF-Expand-Label(finished_key,
 * "finished"), transcript_hash) and writes it into the handshake message at
 * out, setting out->len. finished_key (the server handshake traffic
 * secret), the transcript hash and verify_data are Hash.length bytes.
 * Returns 1, or 0 if it does not fit. */
int sflight_finished_suite(
    u16         suite,
    const u8*   finished_key,
    const u8*   transcript_hash,
    wired_obuf* out);

#endif
