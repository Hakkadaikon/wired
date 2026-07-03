#ifndef QUIC_H3_STREAM_TYPE_H
#define QUIC_H3_STREAM_TYPE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2. A unidirectional stream begins with a varint stream type:
 * 0x00 control, 0x01 push, 0x02 QPACK encoder, 0x03 QPACK decoder. */

/* Read the leading stream-type varint. On success *type holds the type and
 * *consumed the bytes read. Returns 1 ok, 0 if truncated. */
int quic_h3_stream_type_parse(quic_span buf, u64 *type, usz *consumed);

int quic_h3_stream_type_is_control(u64 type);
int quic_h3_stream_type_is_push(u64 type);
int quic_h3_stream_type_is_qpack(u64 type);

#endif
