#ifndef QUIC_H3CANCEL_H
#define QUIC_H3CANCEL_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1.1. A client that no longer needs the response to a request
 * cancels it by resetting the request stream: RESET_STREAM abruptly ends the
 * sending part and STOP_SENDING asks the peer to stop, both carrying the
 * application error code H3_REQUEST_CANCELLED (RFC 9114 8.1, 0x010c). */

/* Build the RESET_STREAM + STOP_SENDING pair that cancels the request on
 * stream_id. final_size is the number of request-body bytes already sent.
 * Writes both frames into out; out->len receives the total written.
 * Returns 1 on success, 0 if out is too small. */
int quic_h3cancel_request(u64 stream_id, u64 final_size, quic_obuf* out);

#endif
