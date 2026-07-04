#ifndef QUIC_SALPN_CH_EXT_H
#define QUIC_SALPN_CH_EXT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.2: locate one extension inside a ClientHello handshake message.
 * ch_msg points at the message (msg_type(1) length(3) body). The body is
 * legacy_version(2) random(32) session_id(1+) cipher_suites(2+) compression(1+)
 * extensions(2+). */

/* Find extension ext_type. On success sets *ext (a view into ch_msg.p) and
 * returns 1; returns 0 if absent or any length field overruns ch_msg.n. */
int quic_salpn_find_extension(quic_span ch_msg, u16 ext_type, quic_span* ext);

#endif
