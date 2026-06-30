#ifndef QUIC_STP_SERVER_TP_H
#define QUIC_STP_SERVER_TP_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 18.2. Build the server's transport parameters into out (cap bytes).
 * original_dcid is the DCID of the client's first Initial (RFC 9000 7.3);
 * initial_scid is the server's source connection id. On success writes the
 * TLV sequence and sets *out_len; returns 1. Returns 0 if it does not fit. */
int quic_stp_build_server(const u8 *original_dcid, u8 odcid_len,
                          const u8 *initial_scid, u8 scid_len,
                          u8 *out, usz cap, usz *out_len);

#endif
