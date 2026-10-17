#ifndef APP_HTTP3_CORE_H3_FRAME_IMPL_H
#define APP_HTTP3_CORE_H3_FRAME_IMPL_H

/* Internal to the frame*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/core/h3/frame.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* A write cursor: the output buffer, its capacity, and the write offset,
 * folded into one parameter so the frame-head helpers below stay <=3 args. */
typedef struct {
  u8* buf;
  usz cap;
  usz off;
} h3frame_wcur;

/* A read cursor: the input buffer, its length, and the read offset. */
typedef struct {
  const u8* buf;
  usz       n;
  usz       off;
} h3frame_rcur;

int h3frame_put_head(h3frame_wcur* w, u64 type, u64 len);
int h3frame_get_head(h3frame_rcur* r, u64* type, u64* len);

#endif
