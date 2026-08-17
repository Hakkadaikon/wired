#include "tls/handshake/roles/sflight/finished_build.h"

#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"

int sflight_finished(
    const u8* finished_key, const u8* transcript_hash, wired_obuf* out) {
  usz off;
  if (out->cap < 4 + TLS_VERIFY_DATA) return 0;
  off = hs_begin(out->p, out->cap, HS_FINISHED);
  tls_finished_verify_data(finished_key, transcript_hash, out->p + off);
  out->len = off + TLS_VERIFY_DATA;
  hs_finish(out->p, out->len);
  return 1;
}
