#include "app/http3/server/srvrun/srvrun_impl.h"

/* a and b differ at most in the peer's port (same local socket and peer
 * address) -- k equal to the last validated path included. */
int srvrun_path_port_only(const pathsel_key* a, const pathsel_key* b) {
  return a->fd == b->fd && ct_diffn(a->peer.addr, b->peer.addr, 16) == 0;
}

/* RFC 9000 9.4: k (the send path or the target about to become it) has
 * just been validated. Unless only the peer's port changed from the last
 * validated path, the congestion controller and RTT estimator restart at
 * their initial values, and packets already sent (on the old path) stop
 * feeding them (srvrun_cc_range / srvrun_feed_acks: cc_from_pn). */
void srvrun_path_cc_restart(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k) {
  if (srvrun_path_port_only(&c->path.last_valid, k)) {
    return;
  }
  cc_init_algo(&c->cc, srvrun_cc_algo(cfg));
  hystart_init(&c->hs);
  rtt_init(&c->rtt);
  c->srtt_ms        = 0;
  c->latest_rtt_ms  = 0;
  c->mig.cc_from_pn = c->l.tx_pn;
}
