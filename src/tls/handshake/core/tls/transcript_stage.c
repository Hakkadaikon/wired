#include "tls/handshake/core/tls/transcript_stage.h"

/* RFC 8446 7.1 */

void quic_transcript_ch_sh(
    const quic_transcript* t, u8 out[QUIC_SHA256_DIGEST]) {
  quic_transcript_hash(t, out);
}

void quic_transcript_ch_sfin(
    const quic_transcript* t, u8 out[QUIC_SHA256_DIGEST]) {
  quic_transcript_hash(t, out);
}
