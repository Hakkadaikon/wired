#include "app/http3/core/h3/errclass.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/grease.h"

int quic_h3_error_is_known(u64 code) {
  /* RFC 9114 8.1: contiguous block QUIC_H3_NO_ERROR..QUIC_H3_VERSION_FALLBACK.
   */
  return code >= QUIC_H3_NO_ERROR && code <= QUIC_H3_VERSION_FALLBACK;
}

int quic_h3_error_is_reserved(u64 code) {
  return quic_h3_is_reserved(code); /* RFC 9114 8.1 grease: 0x1f*N + 0x21 */
}

u64 quic_h3_error_send_value(u64 code, u64 grease_id) {
  if (code != QUIC_H3_NO_ERROR) return code;
  return grease_id ? grease_id : code;
}
