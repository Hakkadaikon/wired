#include "tls/handshake/core/tls/transcript.h"

/* RFC 8446 4.4.1 */

void quic_transcript_init(quic_transcript* t) { quic_sha256_init(&t->h); }

void quic_transcript_add(quic_transcript* t, const u8* msg, usz len) {
  quic_sha256_update(&t->h, msg, len);
}

void quic_transcript_hash(
    const quic_transcript* t, u8 out[QUIC_SHA256_DIGEST]) {
  quic_sha256_ctx copy = t->h; /* finalize a copy; running state survives */
  quic_sha256_final(&copy, out);
}
