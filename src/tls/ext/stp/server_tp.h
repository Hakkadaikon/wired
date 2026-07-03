#ifndef QUIC_STP_SERVER_TP_H
#define QUIC_STP_SERVER_TP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 18.2. Build the server's transport parameters into out->p
 * (out->cap bytes). original_dcid is the DCID of the client's first Initial
 * (RFC 9000 7.3); initial_scid is the server's source connection id. On
 * success writes the TLV sequence and sets out->len; returns 1. Returns 0 if
 * it does not fit. */
int quic_stp_build_server(
    quic_span original_dcid, quic_span initial_scid, quic_obuf *out);

#endif
