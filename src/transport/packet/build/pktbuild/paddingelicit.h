#ifndef QUIC_PKTBUILD_PADDINGELICIT_H
#define QUIC_PKTBUILD_PADDINGELICIT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 13.2.7: an endpoint sending only non-ack-eliciting packets (e.g.
 * PADDING-only) risks going unacknowledged forever, since there is nothing
 * for the peer to ACK. An endpoint in that state periodically bundles an
 * ack-eliciting frame (e.g. PING) to force a round trip.
 *
 * last_eliciting_at: clock reading of the last packet sent that contained an
 * ack-eliciting frame (quic_pktbuild_is_eliciting). now: current clock
 * reading. pto: current Probe Timeout. Returns 1 once at least one PTO has
 * elapsed since the last ack-eliciting send, meaning the next packet should
 * have an ack-eliciting frame bundled in; 0 otherwise. */
int quic_pktbuild_padding_elicit_due(u64 last_eliciting_at, u64 now, u64 pto);

#endif
