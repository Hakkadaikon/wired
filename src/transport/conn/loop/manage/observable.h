#ifndef MANAGE_OBSERVABLE_H
#define MANAGE_OBSERVABLE_H

#include "common/platform/sys/syscall.h"

/* RFC 9312 2/3: which header fields an on-path observer can read in the
 * clear. Long-header Version and Connection IDs are exposed; the spin bit
 * is observable in every short-header packet; everything else a short
 * header carries (key phase meaning, packet number, payload) is protected. */

#define OBS_VERSION 0  /* long-header version field */
#define OBS_DCID 1     /* destination connection ID */
#define OBS_SCID 2     /* source connection ID (long header only) */
#define OBS_SPIN 3     /* short-header latency spin bit */
#define OBS_KEYPHASE 4 /* short-header key phase bit (protected) */
#define OBS_PAYLOAD 5  /* encrypted payload */

/* True if field_id is observable in the clear, given header form
 * (is_long != 0 for a long header). RFC 9312 2/3. */
int observable_field(int field_id, int is_long);

#endif
