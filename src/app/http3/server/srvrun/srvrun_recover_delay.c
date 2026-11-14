#include "app/http3/server/srvrun/srvrun_impl.h"
#include "transport/recovery/detect/lossdrive/lossdelay.h"

/* The delays and totals loss recovery (srvrun_recover.c) reads; split off
 * for the Halstead file cap. */

/* RFC 9002 6.1.2 / A.10: loss_delay = max(kTimeThreshold *
 * max(smoothed_rtt, latest_rtt), kGranularity), in us. An estimator that
 * was never initialized (rtt_init seeds kInitialRtt, so only a bare
 * zeroed connection has smoothed_rtt 0 without a sample) skips the time
 * threshold instead: 0. */
u64 srvrun_loss_delay_us(const srvrun_conn* c) {
  if (!c->rtt.have_sample && !c->rtt.smoothed_rtt) {
    return 0;
  }
  return lossdrive_loss_delay(
      c->rtt.smoothed_rtt, c->latest_rtt_ms * 1000, RTT_GRANULARITY);
}

/* RFC 9000 18.2: the peer's max_ack_delay (default 25ms), in us. */
u64 srvrun_peer_max_ack_delay_us(const srvrun_conn* c) {
  u64 p1 = c->s.sdrv.peer_max_ack_delay_p1;
  return (p1 ? p1 - 1 : 25) * 1000;
}

/* RFC 9002 2 / 7: bytes in flight -- the send sessions' STREAM slices, the
 * rest of every in-flight 1-RTT packet the record counts, and the boot
 * flight until its keys are discarded. */
usz srvrun_bytes_in_flight(const srvrun_conn* c) {
  return c->acct_inflight + c->l.ackst.sent.total_in_flight +
         srvrun_boot_inflight(c);
}
