#ifndef QUIC_MANAGE_RTTOBS_H
#define QUIC_MANAGE_RTTOBS_H

/* RFC 9312 3.5: an on-path observer can estimate RTT from the latency spin
 * bit by timing the edges where its value flips. A usable sample needs the
 * spin bit to be enabled on the connection and an observed edge. */

/* True if the spin value changed between two consecutive observed packets. */
int quic_rttobs_is_edge(int prev_spin, int cur_spin);

/* True if an RTT sample can be taken: spin signalling is enabled and an edge
 * was seen. */
int quic_rttobs_sample_ok(int spin_enabled, int saw_edge);

#endif
