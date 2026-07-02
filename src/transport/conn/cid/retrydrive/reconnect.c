#include "transport/conn/cid/retrydrive/reconnect.h"

#include "common/bytes/util/bytes.h"

/* RFC 9000 17.2.5: token and SCID must fit the reconnection-state buffers. */
static int fits(usz token_len, usz scid_len) {
  return token_len <= sizeof(((quic_retrydrive_state *)0)->token) &&
         scid_len <= QUIC_MAX_CID_LEN;
}

/* RFC 9000 17.2.5.2 */
int quic_retrydrive_apply(
    quic_span retry_token, quic_span retry_scid, quic_retrydrive_state *out) {
  usz off = 0;
  if (!fits(retry_token.n, retry_scid.n)) return 0;
  quic_put_bytes(
      out->token, sizeof out->token, &off, retry_token.p, retry_token.n);
  out->token_len = retry_token.n;
  off            = 0;
  quic_put_bytes(out->dcid, sizeof out->dcid, &off, retry_scid.p, retry_scid.n);
  out->dcid_len     = (u8)retry_scid.n;
  out->received     = 1;
  out->key_rederive = 1;
  return 1;
}
