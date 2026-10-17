#ifndef APP_HTTP3_SERVER_SRVLOOP_BODY_WINDOW_IMPL_H
#define APP_HTTP3_SERVER_SRVLOOP_BODY_WINDOW_IMPL_H

/* Internal to the body_window*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/core/h3/frame.h"
#include "app/http3/server/srvloop/body_window.h"
#include "common/bytes/util/num.h"
#include "common/bytes/varint/varint.h"

/* One pump's cursor: frames are parsed at buf[pos..fr) (fr: the frontier,
 * fixed for the pump) and the window slides once, by pos, at the end. */
typedef struct {
  bodywin*     w;
  u8*          buf;
  usz          pos;
  usz          fr;
  bodywin_sink fn;
  void*        ctx;
} bodywin_run;

/* One capsule pass: the reassembly buffer plus the capsule receiver. */
typedef struct {
  bodywin_capq*      q;
  bodywin_capsule_fn fn;
  void*              ctx;
} bodywin_capctx;

usz bodywin_head(const u8* p, usz n, u64* type, u64* len);

#endif
