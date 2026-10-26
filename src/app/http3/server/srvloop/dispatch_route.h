#ifndef APP_HTTP3_SERVER_SRVLOOP_DISPATCH_ROUTE_H
#define APP_HTTP3_SERVER_SRVLOOP_DISPATCH_ROUTE_H

/* Internal to the dispatch*.c pieces: request-stream routing and completion
 * (split out of dispatch_impl.h to keep it under the Halstead file cap).
 * Not public API. */

#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/respond.h"
#include "app/http3/server/srvloop/dispatch.h"
#include "app/http3/server/srvloop/srvloop.h"

void srvloop_drive_complete(
    wired_h3srv_state*               h3,
    wired_srvloop_reqacc*            acc,
    const wired_srvloop_dispatch_in* in);
void srvloop_drive_complete_hq09(
    wired_srvloop_reqacc* acc, const wired_srvloop_dispatch_in* in);
wired_srvloop_reqacc srvloop_route_slot_acc(wired_srvloop_stream_slot* slot);
int                  srvloop_route_request_frames(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload, u64* touched);
void srvloop_qdec_cancel_id(wired_srvloop* l, u64 id);
void srvloop_qdec_cancel_slot(wired_srvloop* l, int i);
void srvloop_route_qpack_ack(wired_srvloop* l, int i);
void srvloop_route_note_done(wired_srvloop* l, int i);
void srvloop_route_note_frame_unexpected(wired_srvloop* l, int i);
void srvloop_route_note_malformed(wired_srvloop* l, int i);
void srvloop_route_dispatch_complete(
    const wired_srvloop_dispatch_ctx* ctx,
    wired_srvloop_reqacc*             acc,
    const wired_srvloop_dispatch_in*  sin);
void srvloop_route_note_qpack(wired_srvloop* l, int i);
void srvloop_route_note_result(wired_srvloop* l, int i, int got);
int  srvloop_route_complete_over(const wired_srvloop_dispatch_ctx* ctx, int i);
int  srvloop_route_body_on(const wired_srvloop_dispatch_ctx* ctx);
usz  srvloop_route_body_head_len(const wired_srvloop_stream_slot* slot);
int  srvloop_route_body_decode(
    const wired_srvloop_dispatch_ctx* ctx,
    wired_srvloop_stream_slot*        slot,
    usz                               n);
void srvloop_route_complete_slot(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in,
    int                               i);
int srvloop_reassemble_and_drive(
    const wired_srvloop_dispatch_ctx* ctx, const wired_srvloop_dispatch_in* in);

#endif
