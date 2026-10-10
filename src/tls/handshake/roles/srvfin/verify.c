#include "tls/handshake/roles/srvfin/verify.h"

#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/suitehash.h"

/* RFC 8446 4.4.4: a well-formed client Finished is a Finished-typed handshake
 * message whose body is exactly the verify_data length (Hash.length). */
static int is_finished_msg(usz off, u8 type, usz body_len, usz want) {
  return off != 0 && type == HS_FINISHED && body_len == want;
}

/* RFC 8446 4.4.4 */
int srvfin_verify_client_finished_suite(
    u16        suite,
    wired_span client_finished_msg,
    const u8*  client_hs_traffic_secret,
    const u8*  transcript_hash) {
  u8  type;
  usz body_len, off;
  off = hs_parse(client_finished_msg, &type, &body_len);
  if (!is_finished_msg(off, type, body_len, tls_hash_of(suite)->len)) return 0;
  return tls_finished_check_suite(
      suite, client_hs_traffic_secret, transcript_hash,
      client_finished_msg.p + off);
}

int srvfin_verify_client_finished(
    wired_span client_finished_msg,
    const u8   client_hs_traffic_secret[HKDF_PRK],
    const u8   transcript_hash[SHA256_DIGEST]) {
  return srvfin_verify_client_finished_suite(
      TLS_AES_128_GCM_SHA256, client_finished_msg, client_hs_traffic_secret,
      transcript_hash);
}
