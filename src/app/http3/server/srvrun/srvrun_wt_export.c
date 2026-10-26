#include "app/http3/server/srvrun/srvrun_impl.h"
#include "app/webtransport/exporter/exporter.h"

/* draft-ietf-webtrans-http3-16 4.8: the session ID in the Exporter Context
 * is s's CONNECT stream id; the secret and its hash come from the
 * connection's own key schedule (RFC 8446 7.1/7.5). */
int wired_server_wt_exporter(
    wired_wt_session* s,
    wired_span        label,
    wired_span        context,
    wired_mspan       out) {
  srvrun_conn* c = srvrun_session_conn(s);
  const u8*    secret;
  if (!c || !keysched_exporter_secret(&c->s.sched, &secret)) {
    return 0;
  }
  return wt_exporter(
      c->s.sched.suite, secret, s->connect_stream_id, label, context, out);
}
