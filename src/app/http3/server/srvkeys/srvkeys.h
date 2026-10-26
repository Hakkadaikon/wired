#ifndef WIRED_SRVKEYS_SRVKEYS_H
#define WIRED_SRVKEYS_SRVKEYS_H

#include "common/platform/sys/syscall.h"

/** @file
 * Process-wide secret seeds a server derives its rotating session-ticket
 * keys (RFC 8446 4.6.1) and Retry-token keys (RFC 9000 8.1.3) from. Drawn
 * once from the CSPRNG, never compiled into the binary, so a binary's
 * reader cannot forge either. A restart draws new seeds: tickets and Retry
 * tokens issued before it no longer open. Every server entry point calls
 * srvkeys_ready before forking workers or starting threads, so all of them
 * share one draw. */

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

#endif
