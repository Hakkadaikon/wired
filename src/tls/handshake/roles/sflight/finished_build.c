#include "tls/handshake/roles/sflight/finished_build.h"

#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/suitehash.h"

int sflight_finished_suite(
    u16         suite,
    const u8*   finished_key,
    const u8*   transcript_hash,
    wired_obuf* out) {
  usz off, n = tls_hash_of(suite)->len;
  if (out->cap < 4 + n) return 0;
  off = hs_begin(out->p, out->cap, HS_FINISHED);
  tls_finished_verify_data_suite(
      suite, finished_key, transcript_hash, out->p + off);
  out->len = off + n;
  hs_finish(out->p, out->len);
  return 1;
}

int sflight_finished(
    const u8* finished_key, const u8* transcript_hash, wired_obuf* out) {
  return sflight_finished_suite(
      TLS_AES_128_GCM_SHA256, finished_key, transcript_hash, out);
}
