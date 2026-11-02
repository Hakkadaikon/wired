#include "app/http3/server/srvrun/srvrun_impl.h"

/* --- RFC 9000 8/9.3: anti-amplification on unvalidated paths ------------
 *
 * Until a path validates, the server sends it at most three times the
 * bytes it received from it. The counters live on the path's challenge
 * slot (pathsel_slot.rx_bytes/tx_bytes); a path without one may be sent
 * 3x the datagram it just sent (pathsel.fresh), any other nothing. The
 * last validated path is exempt, and so is every path before the first
 * live step, where the handshake's own limit applies (8.1). */

/* !seeded keeps the pre-existing behavior before the first live step: the
 * handshake's own budget applies there. */
static int srvrun_path_exempt(const srvrun_conn* c, const pathsel_key* k) {
  return !c->path.seeded || srvrun_path_is_valid(c, k);
}

/* The arrival path of this step's n-byte datagram. */
void srvrun_path_note_rx(const srvrun_step_ctx* ctx, srvrun_conn* c, usz n) {
  pathsel_key a = srvrun_arrival_key(ctx);
  pathsel_note_rx(&c->path, &a, n);
}

/* Bytes k may still be sent. */
u64 srvrun_path_budget(srvrun_conn* c, const pathsel_key* k) {
  if (srvrun_path_exempt(c, k)) {
    return PATHSEL_NO_LIMIT;
  }
  return pathsel_budget(&c->path, k);
}

/* 1 if an n-byte datagram to k fits its budget, which it then spends. */
int srvrun_path_spend(srvrun_conn* c, const pathsel_key* k, usz n) {
  if (srvrun_path_budget(c, k) < n) {
    return 0;
  }
  pathsel_note_tx(&c->path, k, n);
  return 1;
}

/* srvrun_path_spend for a datagram on c's send path. */
int srvrun_send_spend(const srvrun_cfg* cfg, srvrun_conn* c, usz n) {
  pathsel_key s = srvrun_send_key(cfg, c);
  return srvrun_path_spend(c, &s, n);
}
