#include "tls/handshake/roles/srvfin/verify.h"

#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.4.4: a well-formed client Finished is a Finished-typed handshake
 * message whose body is exactly the verify_data length. */
static int is_finished_msg(usz off, u8 type, usz body_len) {
  return off != 0 && type == QUIC_HS_FINISHED &&
         body_len == QUIC_TLS_VERIFY_DATA;
}

/* RFC 8446 4.4.4 */
int quic_srvfin_verify_client_finished(
    const u8 *client_finished_msg,
    usz       len,
    const u8  client_hs_traffic_secret[QUIC_HKDF_PRK],
    const u8  transcript_hash[QUIC_SHA256_DIGEST]) {
  u8  type;
  usz body_len, off;
  off = quic_hs_parse(quic_span_of(client_finished_msg, len), &type, &body_len);
  if (!is_finished_msg(off, type, body_len)) return 0;
  return quic_tls_finished_check(
      client_hs_traffic_secret, transcript_hash, client_finished_msg + off);
}
