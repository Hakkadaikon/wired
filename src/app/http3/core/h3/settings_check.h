#ifndef QUIC_H3_SETTINGS_CHECK_H
#define QUIC_H3_SETTINGS_CHECK_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 7.2.4.1 / 11.2.2. Setting identifiers 0x02, 0x03, 0x04 and 0x05 are
 * reserved: they were used by HTTP/2 and their receipt on an HTTP/3 connection
 * MUST be treated as an H3_SETTINGS_ERROR. Every other identifier is allowed --
 * known settings (e.g. 0x06 MAX_FIELD_SECTION_SIZE) are honoured and unknown
 * ones are ignored (RFC 9114 7.2.4). */

/* HTTP/2-reserved setting identifiers, forbidden in HTTP/3 SETTINGS. */
#define QUIC_H3_SETTING_RESERVED_LOW 0x02
#define QUIC_H3_SETTING_RESERVED_HIGH 0x05

/* Whether a SETTINGS identifier may appear on an HTTP/3 connection. Returns 0
 * for a reserved HTTP/2 identifier (H3_SETTINGS_ERROR), 1 otherwise. */
int h3_setting_allowed(u64 id);

/* RFC 9297 2.1.1, id 0x33. Kept local to this check rather than shared with
 * h3settings/settings_build.c's own identical #define: that file builds the
 * setting, this one validates a received one, and the two never include each
 * other's headers. */
#define QUIC_H3_SETTING_H3_DATAGRAM 0x33

/* RFC 9297 2.1.1 / 9297-012: the SETTINGS_H3_DATAGRAM value MUST be 0 or 1;
 * any other value received MUST terminate the connection with
 * H3_SETTINGS_ERROR. A setting id other than SETTINGS_H3_DATAGRAM is out of
 * scope for this check and always passes. Returns 0 only for id ==
 * SETTINGS_H3_DATAGRAM with value > 1.
 * @param id    the received SETTINGS identifier
 * @param value the received SETTINGS value
 * @return 1 if allowed, 0 if this is SETTINGS_H3_DATAGRAM with an out-of-
 *   range value (H3_SETTINGS_ERROR) */
int h3_setting_h3_datagram_value_ok(u64 id, u64 value);

#endif
