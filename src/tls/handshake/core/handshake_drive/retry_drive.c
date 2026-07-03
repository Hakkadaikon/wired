#include "tls/handshake/core/handshake_drive/retry_drive.h"

#include "common/bytes/util/bytes.h"
#include "tls/handshake/core/tls/retry_tag.h"
#include "transport/packet/header/packet/retry.h"

/* Copy the parsed token and the Retry SCID (the next DCID) to the outputs. */
static void retry_emit(const quic_retry_packet *r, const quic_retry_process_out *out) {
  usz off = 0;
  quic_put_bytes(out->token->p, out->token->cap, &off, r->token, r->token_len);
  out->token->len = r->token_len;
  off             = 0;
  quic_put_bytes(out->new_dcid, r->scid_len, &off, r->scid, r->scid_len);
  *out->new_dcil = r->scid_len;
}

int quic_retry_process(
    quic_span retry_pkt, quic_span orig_dcid, const quic_retry_process_out *out) {
  quic_retry_packet r;
  if (quic_retry_parse(retry_pkt.p, retry_pkt.n, &r) == 0) return 0;
  if (!quic_retry_verify(orig_dcid, retry_pkt)) return 0;
  retry_emit(&r, out);
  return 1;
}

int quic_retry_already(int state) { return state != 0; }
