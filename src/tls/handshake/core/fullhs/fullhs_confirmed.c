#include "tls/handshake/core/fullhs/fullhs_impl.h"

static void install_app(fullhs* h);

int fullhs_send_finished(fullhs* h, wired_obuf* out) {
  u8 th[SHA256_DIGEST];
  if (out->cap < HS_HEADER + TLS_VERIFY_DATA) {
    return 0;
  }
  out->p[0] = HSD_FINISHED;
  out->p[1] = 0;
  out->p[2] = 0;
  out->p[3] = TLS_VERIFY_DATA;
  fullhs_tr_hash(h, th);
  tls_finished_verify_data(h->hs_traffic_self, th, out->p + HS_HEADER);
  out->len = HS_HEADER + TLS_VERIFY_DATA;
  return fullhs_fold_finished(h, out->p, out->len);
}

/* Install the 1-RTT keys for our send direction, unlocking 1-RTT sending. */
static void install_app(fullhs* h) {
  const initial_keys* k;
  int                 which = h->is_server ? KS_SERVER_AP : KS_CLIENT_AP;
  if (keysched_get(&h->tls->ks, which, &k)) {
    keyset_install(&h->tls->keys, LEVEL_ONERTT, k);
  }
}

/* RFC 8446 7.1: application_traffic_secret_0 is derived over the transcript
 * through the server's Finished, which is the last message buffered once the
 * peer's Finished was accepted. */
int fullhs_advance_application(fullhs* h) {
  if (!hsdriver_complete(&h->tls->hs)) {
    return 0;
  }
  keysched_advance_master(&h->tls->ks, h->tr, h->master_tr_len);
  install_app(h);
  return 1;
}

int fullhs_confirmed(fullhs* h) {
  if (!hsdriver_recv(&h->tls->hs, HSD_HANDSHAKE_DONE, HSD_PROT_1RTT)) {
    return 0;
  }
  if (key_should_discard_handshake(hsdriver_confirmed(&h->tls->hs))) {
    keyset_discard(&h->tls->keys, LEVEL_HANDSHAKE);
  }
  return 1;
}

int fullhs_is_complete(const fullhs* h) {
  return hsdriver_complete(&h->tls->hs);
}

int fullhs_is_confirmed(const fullhs* h) {
  return hsdriver_confirmed(&h->tls->hs);
}
