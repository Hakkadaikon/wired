#include "transport/recovery/stats/stats.h"

void stats_rtt_get(const rtt* r, stats_rtt* out) {
  out->smoothed_rtt = r->smoothed_rtt;
  out->min_rtt      = r->min_rtt;
  out->rttvar       = r->rttvar;
}

void stats_cc_get(const cc* c, stats_cc* out) {
  out->cwnd        = c->cwnd;
  out->ssthresh    = c->ssthresh;
  out->in_recovery = c->in_recovery;
}

/* True if slot i is a tracked, currently-lost packet. */
static int is_lost_slot(const sent* s, usz i) {
  return s->pkts[i].used && s->pkts[i].state == PKT_LOST;
}

/* Count tracked slots currently in PKT_LOST state. */
static usz count_lost(const sent* s) {
  usz lost = 0;
  for (usz i = 0; i < SENT_CAP; i++)
    if (is_lost_slot(s, i)) lost++;
  return lost;
}

void stats_sent_get(const sent* s, stats_sent* out) {
  out->bytes_in_flight = s->bytes_in_flight;
  out->lost            = count_lost(s);
}
