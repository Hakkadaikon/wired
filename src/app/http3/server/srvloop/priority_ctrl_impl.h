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

#endif
