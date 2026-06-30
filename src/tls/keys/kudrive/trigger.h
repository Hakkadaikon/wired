#ifndef QUIC_KUDRIVE_TRIGGER_H
#define QUIC_KUDRIVE_TRIGGER_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.1/6.5: an endpoint MUST NOT initiate a key update before the
 * handshake is confirmed; once confirmed, an update is initiated when the
 * packets sent under the current key reach an update threshold (e.g. an AEAD
 * usage limit). Returns 1 when an update should be initiated, else 0. */
int quic_kudrive_should_initiate(u64 packets_sent_in_phase,
                                 u64 update_threshold,
                                 int handshake_confirmed);

#endif
