#ifndef QUIC_KEYUPDATE_OLDKEY_H
#define QUIC_KEYUPDATE_OLDKEY_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.1/6.5: after a key update the prior key is retained for three
 * times the PTO so that delayed packets protected with it can still be
 * decrypted, then discarded. update_time, now and pto share one time unit. */

/* 1 while the old key must still be retained (now within the 3*PTO window). */
int quic_oldkey_retain(u64 update_time, u64 now, u64 pto);

/* 1 once the old key may be discarded (3*PTO elapsed since the update). */
int quic_oldkey_can_discard(u64 update_time, u64 now, u64 pto);

#endif
