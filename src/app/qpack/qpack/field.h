#ifndef QUIC_QPACK_FIELD_H
#define QUIC_QPACK_FIELD_H

#include "common/bytes/span/span.h"

/** A QPACK field line's (name, value) pair as borrowed views (encoder input
 * / decoder table lookups). */
typedef struct {
  quic_span name;  /**< field name view */
  quic_span value; /**< field value view */
} quic_qpack_field;

/** The caller-owned output buffers a QPACK decoder fills. */
typedef struct {
  quic_obuf name;  /**< output buffer for the field name */
  quic_obuf value; /**< output buffer for the field value */
} quic_qpack_fieldbuf;

#endif
