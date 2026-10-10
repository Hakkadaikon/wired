#include "tls/handshake/core/tls/transcript.h"

#include "tls/handshake/core/tls/cipher.h"

/* RFC 8446 4.4.1 */

void transcript_init(transcript* t) {
  sha256_init(&t->h);
  sha384_init(&t->h384);
}

void transcript_add(transcript* t, const u8* msg, usz len) {
  sha256_update(&t->h, msg, len);
  sha512_update(&t->h384, msg, len);
}

void transcript_hash(const transcript* t, u8 out[SHA256_DIGEST]) {
  sha256_ctx copy = t->h; /* finalize a copy; running state survives */
  sha256_final(&copy, out);
}

static void transcript_hash384(const transcript* t, u8* out) {
  sha512_ctx copy = t->h384;
  sha384_final(&copy, out);
}

void transcript_hash_suite(const transcript* t, u16 suite, u8* out) {
  if (suite == TLS_AES_256_GCM_SHA384)
    transcript_hash384(t, out);
  else
    transcript_hash(t, out);
}
