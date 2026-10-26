#include "tls/handshake/core/sdrv/sdrv_impl.h"

/* RFC 9000 7.4 / 18.2: a malformed, server-only or out-of-range transport
 * parameter (max_udp_payload_size < 1200, ack_delay_exponent > 20,
 * max_ack_delay >= 2^14, active_connection_id_limit < 2) from the client is
 * a TRANSPORT_PARAMETER_ERROR. */
int sdrv_ch_check_client_tp(sdrv* s, const u8* ch_msg, usz ch_len) {
  if (tparam_client_tp_ok(sdrv_tp_seq(ch_msg, ch_len))) {
    return 1;
  }
  s->last_error = ERR_TRANSPORT_PARAMETER_ERROR;
  return 0;
}

/* RFC 9000 7.3: initial_source_connection_id is present and equals the
 * Source CID of the client's Initial -- checked only once the QUIC layer
 * has recorded that SCID (sdrv_set_peer_scid). */
static int sdrv_iscid_ok(const sdrv* s, wired_span tp) {
  wired_span got;
  stp_out    out_v = {0, &got};
  if (!s->peer_scid_set) {
    return 1;
  }
  return stp_parse(tp, TP_INITIAL_SOURCE_CONNECTION_ID, &out_v) &&
         tparam_check_initial_scid(
             got, wired_span_of(s->peer_scid, s->peer_scid_len));
}

/* RFC 9000 7.3: an absent or mismatched initial_source_connection_id MUST
 * be treated as a TRANSPORT_PARAMETER_ERROR. */
int sdrv_ch_check_iscid(sdrv* s, const u8* ch_msg, usz ch_len) {
  if (sdrv_iscid_ok(s, sdrv_tp_seq(ch_msg, ch_len))) {
    return 1;
  }
  s->last_error = ERR_TRANSPORT_PARAMETER_ERROR;
  return 0;
}
