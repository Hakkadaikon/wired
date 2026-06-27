#ifndef QUIC_H3_SETTINGS_CHECK_H
#define QUIC_H3_SETTINGS_CHECK_H

#include "sys/syscall.h"

/* RFC 9114 7.2.4.1 / 11.2.2. Setting identifiers 0x02, 0x03, 0x04 and 0x05 are
 * reserved: they were used by HTTP/2 and their receipt on an HTTP/3 connection
 * MUST be treated as an H3_SETTINGS_ERROR. Every other identifier is allowed --
 * known settings (e.g. 0x06 MAX_FIELD_SECTION_SIZE) are honoured and unknown
 * ones are ignored (RFC 9114 7.2.4). */

/* HTTP/2-reserved setting identifiers, forbidden in HTTP/3 SETTINGS. */
#define QUIC_H3_SETTING_RESERVED_LOW  0x02
#define QUIC_H3_SETTING_RESERVED_HIGH 0x05

/* Whether a SETTINGS identifier may appear on an HTTP/3 connection. Returns 0
 * for a reserved HTTP/2 identifier (H3_SETTINGS_ERROR), 1 otherwise. */
int quic_h3_setting_allowed(u64 id);

#endif
