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
