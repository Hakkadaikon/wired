#ifndef QUIC_QPACK_FIELD_H
#define QUIC_QPACK_FIELD_H

#include "common/bytes/span/span.h"

/** A QPACK field line's (name, value) pair as borrowed views (encoder input
 * / decoder table lookups). */
typedef struct {
  wired_span name;  /**< field name view */
  wired_span value; /**< field value view */
} qpack_field;

/** The caller-owned output buffers a QPACK decoder fills. */
typedef struct {
  wired_obuf name;  /**< output buffer for the field name */
  wired_obuf value; /**< output buffer for the field value */
} qpack_fieldbuf;

#endif
