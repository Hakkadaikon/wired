#ifndef QUIC_H3_SETTINGS_DUP_H
#define QUIC_H3_SETTINGS_DUP_H

#include "sys/syscall.h"

/* RFC 9114 7.2.4. The same SETTINGS identifier MUST NOT occur more than once
 * in a SETTINGS frame; a repeated identifier is treated as H3_SETTINGS_ERROR. */

#define QUIC_H3_SETTINGS_SEEN_MAX 16

typedef struct {
    usz n;
    u64 ids[QUIC_H3_SETTINGS_SEEN_MAX];
} quic_h3_settings_seen;

/* Reset the set of seen identifiers to empty. */
void quic_h3_settings_seen_init(quic_h3_settings_seen *s);

/* Record identifier id. Returns 0 if id was already seen (duplicate ->
 * H3_SETTINGS_ERROR) or the set is full, 1 if it is newly recorded. */
int quic_h3_settings_mark(quic_h3_settings_seen *s, u64 id);

#endif
