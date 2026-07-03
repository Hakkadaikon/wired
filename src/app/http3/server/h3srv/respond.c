#include "app/http3/server/h3srv/respond.h"

#include "app/http3/core/h3conn/response.h"

/* RFC 9114 4.1 */
int quic_h3srv_on_request(
    quic_h3srv_state        *st,
    const quic_h3srv_req_in *in,
    quic_h3reqdrive_req     *req) {
  if (!quic_h3reqdrive_recv_get(in->stream_data, in->scratch, req)) return 0;
  st->request_seen = 1;
  return 1;
}

/* RFC 9114 4.1 / 6.2.1: own SETTINGS-first and a received request are both
 * preconditions of producing a response. */
static int may_respond(const quic_h3srv_state *st) {
  return st->settings_sent && st->request_seen;
}

/* RFC 9114 4.1 / 4.3.2 */
int quic_h3srv_build_response(
    const quic_h3srv_state *st, const quic_h3srv_send_in *in, quic_obuf *out) {
  if (!may_respond(st)) return 0;
  return quic_h3conn_send_response(in->stream_id, &in->resp, out);
}

/* RFC 9110 9.3.2: method == "HEAD" (exact, case-sensitive per RFC 9110 9.1).
 * XOR-accumulate avoids a per-octet branch; only the length guard and the loop
 * count toward complexity. */
static int is_head(quic_span method) {
  static const u8 head[4] = {'H', 'E', 'A', 'D'};
  u8              diff    = (method.n != 4);
  for (usz i = 0; i < 4 && i < method.n; i++) diff |= method.p[i] ^ head[i];
  return diff == 0;
}

/* RFC 9110 9.3.2: drop the body for a HEAD response (HEADERS only, no DATA). */
int quic_h3srv_build_response_for_method(
    const quic_h3srv_state              *st,
    const quic_h3srv_resp_for_method_in *in,
    quic_obuf                           *out) {
  quic_h3srv_send_in send = in->send;
  if (is_head(in->method)) send.resp.body = quic_span_of(0, 0);
  return quic_h3srv_build_response(st, &send, out);
}
