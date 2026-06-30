#ifndef QUIC_KEYUPDATE_INITIATE_H
#define QUIC_KEYUPDATE_INITIATE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.1: an endpoint must not start a key update until the handshake
 * is confirmed, and must not start a new one until at least three times the
 * PTO has passed since the prior update completed (preventing back-to-back
 * updates that would exhaust the peer's retained keys). */

/* 1 if a key update may begin now: handshake confirmed and 3*PTO elapsed
 * since last_update. */
int quic_keyupdate_may_initiate(int handshake_confirmed, u64 last_update,
                                u64 now, u64 pto);

#endif
