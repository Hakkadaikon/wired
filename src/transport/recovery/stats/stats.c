#include "transport/recovery/stats/stats.h"

void quic_stats_rtt_get(const quic_rtt* r, quic_stats_rtt* out) {
  out->smoothed_rtt = r->smoothed_rtt;
  out->min_rtt      = r->min_rtt;
  out->rttvar       = r->rttvar;
}

void quic_stats_cc_get(const quic_cc* c, quic_stats_cc* out) {
  out->cwnd        = c->cwnd;
  out->ssthresh    = c->ssthresh;
  out->in_recovery = c->in_recovery;
}

/* True if slot i is a tracked, currently-lost packet. */
static int is_lost_slot(const quic_sent* s, usz i) {
  return s->pkts[i].used && s->pkts[i].state == QUIC_PKT_LOST;
}

/* Count tracked slots currently in QUIC_PKT_LOST state. */
static usz count_lost(const quic_sent* s) {
  usz lost = 0;
  for (usz i = 0; i < QUIC_SENT_CAP; i++)
    if (is_lost_slot(s, i)) lost++;
  return lost;
}

void quic_stats_sent_get(const quic_sent* s, quic_stats_sent* out) {
  out->bytes_in_flight = s->bytes_in_flight;
  out->lost            = count_lost(s);
}
