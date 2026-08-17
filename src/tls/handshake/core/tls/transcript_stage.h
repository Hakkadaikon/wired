#ifndef QUIC_TLS_TRANSCRIPT_STAGE_H
#define QUIC_TLS_TRANSCRIPT_STAGE_H

#include "tls/handshake/core/tls/transcript.h"

/* RFC 8446 7.1: transcript hash at the derivation stages that feed
 * Derive-Secret. Each helper snapshots the running hash; the caller is
 * responsible for having added the messages up to that stage. */

/* After ClientHello..ServerHello (client_handshake/server_handshake secrets).
 */
void transcript_ch_sh(const transcript* t, u8 out[QUIC_SHA256_DIGEST]);

/* After ClientHello..server Finished (master secret derivation input). */
void transcript_ch_sfin(const transcript* t, u8 out[QUIC_SHA256_DIGEST]);

#endif
