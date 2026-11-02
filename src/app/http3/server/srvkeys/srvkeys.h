#ifndef WIRED_SRVKEYS_SRVKEYS_H
#define WIRED_SRVKEYS_SRVKEYS_H

#include "common/platform/sys/syscall.h"
#include "transport/conn/loop/manage/zerortt_seen.h"

/** @file
 * Process-wide secret seeds a server derives its rotating session-ticket
 * keys (RFC 8446 4.6.1) and Retry-token keys (RFC 9000 8.1.3) from. Drawn
 * once from the CSPRNG, never compiled into the binary, so a binary's
 * reader cannot forge either. A restart draws new seeds: tickets and Retry
 * tokens issued before it no longer open. Every server entry point calls
 * srvkeys_ready before forking workers or starting threads, so all of them
 * share one draw. The NEW_TOKEN used-token record lives here too, beside
 * its key: srvworkers already calls srvkeys before it forks but sees
 * srvrun only through its public API, so the record is shared from here. */

/** Bytes per seed (TICKET_KEY_LEN == RETRYTOKEN_KEY == KEYRING_KEY). */
#define SRVKEYS_LEN 32

/** Draw the seeds on first call; later calls only report.
 * @return 1 once the seeds hold CSPRNG bytes, 0 if the draw failed */
int srvkeys_ready(void);

/** The session-ticket seed (drawn on first use if not yet drawn).
 * @return SRVKEYS_LEN bytes, all zero only if srvkeys_ready failed */
const u8* srvkeys_ticket(void);

/** The Retry-token seed (drawn on first use if not yet drawn).
 * @return SRVKEYS_LEN bytes, all zero only if srvkeys_ready failed */
const u8* srvkeys_retry(void);

/** The NEW_TOKEN token key (RFC 9000 8.1.3), drawn with the other seeds.
 * Used as is, not rotated: a NEW_TOKEN token carries its own issue time and
 * expires by it (NEWTOKEN_MAX_AGE_SECS), across key epochs.
 * @return SRVKEYS_LEN bytes, all zero only if srvkeys_ready failed */
const u8* srvkeys_newtoken(void);

/** RFC 9000 8.1.4: the record of NEW_TOKEN tokens already used, so each
 * opens one connection only. Process-local until srvkeys_newtoken_share.
 * @return the tracker every server thread checks tokens against */
zerortt_seen* srvkeys_newtoken_seen(void);

/** Move the used-token record into shared memory so fork(2) children
 * (srvworkers) keep one record with the parent and each other, like
 * sdrv_zerortt_share. Call before forking; a second call is a no-op.
 * @return 1 once shared, 0 if the mapping failed (it stays per process) */
int srvkeys_newtoken_share(void);

#endif
