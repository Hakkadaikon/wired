#ifndef TLS_EXT_TPARAM_TPBLOB_IMPL_H
#define TLS_EXT_TPARAM_TPBLOB_IMPL_H

/* Internal to the tpblob*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"
#include "tls/ext/tparam/tpblob.h"

/* id and value-length read from the blob's header varints. */
typedef struct {
  u64 id;
  u64 len;
} tpblob_hdr;

#endif
