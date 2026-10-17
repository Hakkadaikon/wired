#include "tls/handshake/roles/server/server_impl.h"

static void srv_resumption_master_secret(const wired_server* s, u8* out);

/* RFC 9001 4.9 / RFC 8446 7.1 (0.5-RTT) */
int wired_server_early_send_keys(wired_server* s) {
  if (s->phase != WIRED_SERVER_HS_FLIGHT_SENT) {
    return 0;
  }
  return srvfin_early_send_keys(&s->fin, s->tr, s->tr_through_flight);
}

/* RFC 8446 7.1: resumption_master_secret = Derive-Secret(Master Secret,
 * "res master", ClientHello...client Finished) -- the transcript spans all
 * handshake messages through the CLIENT's Finished, not the server's. This
 * server only ever issues a ticket post-confirmation
 * (wired_server_is_confirmed), by which point tr_through_client_fin is
 * always set -- see wired_server_resumption_secret. */
static void srv_resumption_master_secret(const wired_server* s, u8* out) {
  derive_secret_in in;
  in.secret   = s->sched.master;
  in.label    = wired_span_of((const u8*)"res master", 10);
  in.messages = wired_span_of(s->tr, s->tr_through_client_fin);
  in.suite    = s->sdrv.cipher_suite;
  tls_derive_secret(&in, out);
}

int wired_server_resumption_secret(const wired_server* s, u8* out) {
  if (!wired_server_is_confirmed(s)) {
    return 0;
  }
  srv_resumption_master_secret(s, out);
  return 1;
}
