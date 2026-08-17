#ifndef H3_SETTINGS_DUP_H
#define H3_SETTINGS_DUP_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 7.2.4. The same SETTINGS identifier MUST NOT occur more than once
 * in a SETTINGS frame; a repeated identifier is treated as H3_SETTINGS_ERROR.
 */

#define H3_SETTINGS_SEEN_MAX 16

/** RFC 9114 7.2.4: the set of SETTINGS identifiers already seen on this
 * frame, for duplicate detection. */
typedef struct {
  usz n;
  u64 ids[H3_SETTINGS_SEEN_MAX];
} h3_settings_seen;

/* Reset the set of seen identifiers to empty. */
void h3_settings_seen_init(h3_settings_seen* s);

/* Record identifier id. Returns 0 if id was already seen (duplicate ->
 * H3_SETTINGS_ERROR) or the set is full, 1 if it is newly recorded. */
int h3_settings_mark(h3_settings_seen* s, u64 id);

#endif
