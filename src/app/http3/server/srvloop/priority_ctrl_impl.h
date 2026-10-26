#ifndef APP_HTTP3_SERVER_SRVLOOP_PRIORITY_CTRL_IMPL_H
#define APP_HTTP3_SERVER_SRVLOOP_PRIORITY_CTRL_IMPL_H

/* Internal to the priority_ctrl*.c pieces of this directory: shared types,
 * macros and the functions and tables more than one piece uses. Not public API.
 */

#include "app/http3/core/h3/control.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/priupdate.h"
#include "app/http3/core/h3/stream_type.h"
#include "app/http3/server/h3srv/priupdate.h"
#include "app/http3/server/srvloop/priority_ctrl.h"
#include "app/http3/server/srvloop/srvloop_crit.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9000 16: the leading 0x00 control type varint's own encoded length --
 * always a single byte. */
#define CTRL_TYPE_LEN 1

int  srvloop_ctrl_is_stream_type(u64 type);
int  srvloop_ctrl_leading_type_is_control(const stream_frame* sf);
int  srvloop_ctrl_stream_of(u64 type, wired_span frame, stream_frame* sf);
void srvloop_ctrl_land(wired_srvloop* l, const stream_frame* sf);
void srvloop_ctrl_compact(wired_srvloop* l);
int  srvloop_ctrl_claim(wired_srvloop* l, const stream_frame* sf);
/* RFC 9114 7.2: act on one complete control-stream frame f (SETTINGS,
 * GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, or a type a control stream must not
 * carry), latching any connection error into l->h3peer.error. */
void srvloop_ctrl_frame(wired_srvloop* l, const h3_frame* f);
/* srvloop_h3_fail(l, code) unless ok. */
void srvloop_ctrl_check(wired_srvloop* l, int ok, u16 code);

#endif
