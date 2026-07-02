#ifndef QUIC_QPACK_FIELD_H
#define QUIC_QPACK_FIELD_H

#include "common/bytes/span/span.h"

/* A QPACK field line's (name, value) pair. quic_qpack_field carries borrowed
 * views (encoder input / decoder table lookups); quic_qpack_fieldbuf carries
 * the caller-owned output buffers a decoder fills. */
typedef struct {
  quic_span name;
  quic_span value;
} quic_qpack_field;

typedef struct {
  quic_obuf name;
  quic_obuf value;
} quic_qpack_fieldbuf;

#endif
