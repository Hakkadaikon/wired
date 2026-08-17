#include "tls/handshake/core/tls/transcript.h"

/* RFC 8446 4.4.1 */

void transcript_init(transcript* t) { sha256_init(&t->h); }

void transcript_add(transcript* t, const u8* msg, usz len) {
  sha256_update(&t->h, msg, len);
}

void transcript_hash(const transcript* t, u8 out[QUIC_SHA256_DIGEST]) {
  sha256_ctx copy = t->h; /* finalize a copy; running state survives */
  sha256_final(&copy, out);
}
