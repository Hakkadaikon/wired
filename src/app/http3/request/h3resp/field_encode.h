#ifndef QUIC_H3RESP_FIELD_ENCODE_H
#define QUIC_H3RESP_FIELD_ENCODE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5. Encode a response field section carrying a single :status
 * pseudo-header: the Encoded Field Section Prefix (Required Insert Count 0,
 * Base 0, no dynamic table) followed by the :status field line. A status whose
 * (":status", value) pair exists in the static table is emitted as an Indexed
 * Field Line; otherwise as a Literal Field Line referencing the static :status
 * name. Returns 1 with out->len set, 0 if out lacks capacity. */
int quic_h3resp_encode_status(u16 status, quic_obuf *out);

#endif
