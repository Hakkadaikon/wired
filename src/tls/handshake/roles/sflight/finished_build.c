#include "tls/handshake/roles/sflight/finished_build.h"

#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"

int quic_sflight_finished(
    const u8 *finished_key, const u8 *transcript_hash, quic_obuf *out) {
  usz off;
  if (out->cap < 4 + QUIC_TLS_VERIFY_DATA) return 0;
  off = quic_hs_begin(out->p, out->cap, QUIC_HS_FINISHED);
  quic_tls_finished_verify_data(finished_key, transcript_hash, out->p + off);
  out->len = off + QUIC_TLS_VERIFY_DATA;
  quic_hs_finish(out->p, out->len);
  return 1;
}
