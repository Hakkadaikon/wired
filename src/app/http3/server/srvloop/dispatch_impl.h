#ifndef APP_HTTP3_SERVER_SRVLOOP_DISPATCH_IMPL_H
#define APP_HTTP3_SERVER_SRVLOOP_DISPATCH_IMPL_H

/* Internal to the dispatch*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/datagram/datagram/dgcheck.h"
#include "app/datagram/dgdeliver/dg_recv.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/stream_type.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/request/h3reqdrive/request_parse.h"
#include "app/http3/server/h3srv/peer.h"
#include "app/http3/server/h3srv/respond.h"
#include "app/http3/server/hq09/hq09.h"
#include "app/http3/server/srvloop/dispatch.h"
#include "app/http3/server/srvloop/priority_ctrl.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "app/qpack/qpack/error.h"
#include "app/qpack/qpackdyn/enc_stream.h"
#include "app/rawquic/rawq.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "common/bytes/varint/varint.h"
#include "common/platform/qlog/qlog.h"
#include "common/platform/qlog/qlogevent.h"
#include "transport/packet/frame/frame/connctl.h"
#include "transport/packet/frame/frame/dispatch.h"
#include "transport/packet/frame/frame/flowctl.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/ncid_check.h"
#include "transport/packet/frame/frame/stream_ctl.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/stream/data/appdata/stream_send.h"
#include "transport/stream/data/maxstreams/maxstreams.h"

/* draft-ietf-webtrans-http3-15 4.3: capacity for a stream's leading signal
 * (two varints, each at most 8 bytes -- RFC 9000 16). */
#define WT_SIG_CAP 16

typedef struct {
  wired_srvloop*             l;
  wired_srvloop_stream_slot* slot;
} route_body_call;

typedef void (*raw_land_fn)(wired_srvloop* l, const stream_frame* sf);

int srvloop_is_stream(u64 type);
int srvloop_is_request_stream(u64 stream_id);
int srvloop_is_wt_stream_signal(wired_span data);
int srvloop_sf_is_wt_signalled(const stream_frame* sf);
int srvloop_wt_frame_relevant(const wired_srvloop* l, const stream_frame* sf);
int dispatch_stream(
    wired_h3srv_state*               h3,
    wired_span                       frame,
    const wired_srvloop_dispatch_in* in);
void srvloop_bump_len(wired_srvloop_reqacc* acc, usz end);
int  srvloop_request_stream_of(
    const wired_srvloop* l, u64 type, wired_span frame, stream_frame* sf);
int srvloop_gather_request(
    const wired_srvloop*  l,
    const u8*             payload,
    usz                   len,
    wired_srvloop_reqacc* acc);
usz srvloop_acc_headers_frame_len(const wired_srvloop_reqacc* acc);
int srvloop_req_method_is_connect(const wired_h3reqdrive_req* r);
int srvloop_peek_decode_request(
    const wired_h3srv_state*         h3,
    const wired_srvloop_reqacc*      acc,
    const wired_srvloop_dispatch_in* in,
    usz                              n,
    wired_h3reqdrive_req*            r);
int srvloop_connect_headers_complete(
    const wired_h3srv_state*         h3,
    const wired_srvloop_reqacc*      acc,
    const wired_srvloop_dispatch_in* in);
int srvloop_request_complete(
    const wired_h3srv_state*         h3,
    const wired_srvloop_reqacc*      acc,
    const wired_srvloop_dispatch_in* in);
int srvloop_client_bidi_stream_of(u64 type, wired_span frame, stream_frame* sf);
int srvloop_server_bidi_stream_of(u64 type, wired_span frame, stream_frame* sf);
int srvloop_wt_sig_resolve(
    u8* sig, u8* have, u8* pending, usz* len, const stream_frame* sf);
usz  srvloop_wt_frame_skip(const stream_frame* sf, usz sig_len);
u64  srvloop_wt_frame_abs(const stream_frame* sf, usz sig_len, usz skip);
void srvloop_gather_wt_one(
    const stream_frame* sf, wired_srvloop_wt_stream_slot* slot);
int srvloop_wt_slot_for(wired_srvloop* l, const stream_frame* sf);
int srvloop_wt_sig_ready(
    wired_srvloop_wt_stream_slot* s, const stream_frame* sf);
int srvloop_gather_wt_frame(wired_srvloop* l, u64 type, wired_span frame);
int srvloop_gather_server_bidi_frame(
    wired_srvloop* l, u64 type, wired_span frame);
int  srvloop_gather_wt_stream(wired_srvloop* l, const u8* payload, usz len);
int  srvloop_is_uni_stream(u64 stream_id);
int  srvloop_uni_stream_type_accepted(wired_span data);
void srvloop_uni_stream_type_note_qpack(wired_srvloop* l, wired_span data);
void srvloop_uni_type_mark(wired_srvloop* l, const stream_frame* sf);
int  srvloop_qenc_takes(const wired_srvloop* l, const stream_frame* sf);
void srvloop_gather_qpack_enc(wired_srvloop* l, const stream_frame* sf);
int  srvloop_client_uni_stream_of(u64 type, wired_span frame, stream_frame* sf);
int  srvloop_wt_uni_frame_relevant(
    const wired_srvloop* l, const stream_frame* sf);
void srvloop_gather_wt_uni_one(
    const stream_frame* sf, wired_srvloop_wt_uni_stream_slot* slot);
void dispatch_qlog_stream_received(wired_srvloop* l, const stream_frame* sf);
void srvloop_gather_wt_uni_land(wired_srvloop* l, const stream_frame* sf);
void srvloop_gather_wt_uni_classify(wired_srvloop* l, const stream_frame* sf);
void srvloop_gather_wt_uni_frame(wired_srvloop* l, const stream_frame* sf);
int  srvloop_gather_uni_stream(wired_srvloop* l, const u8* payload, usz len);
int srvloop_gather_ctrl_priupdate(wired_srvloop* l, const u8* payload, usz len);
int srvloop_gather_req_priupdate(wired_srvloop* l, const u8* payload, usz len);
int srvloop_gather_rx_datagrams(wired_srvloop* l, const u8* payload, usz len);
int srvloop_reset_stream_id(u64 type, wired_span frame, u64* stream_id_out);
int srvloop_wt_reset_frame(u64 type, wired_span frame, reset_stream_frame* out);
int srvloop_wt_stop_frame(u64 type, wired_span frame, stop_sending_frame* out);
void srvloop_gather_one_wt_reset(wired_srvloop* l, u64 type, wired_span frame);
void srvloop_gather_one_stream_close(
    wired_srvloop* l, u64 type, wired_span frame);
int  srvloop_is_close_shaped(frame_kind kind, u64 type);
void srvloop_gather_one_max_data(wired_srvloop* l, wired_span frame);
int  srvloop_gather_max_streams_uni(
    wired_srvloop* l, const u8* payload, usz len);
int srvloop_gather_streams_blocked(
    wired_srvloop* l, const u8* payload, usz len);
int srvloop_gather_path_challenge(wired_srvloop* l, const u8* payload, usz len);
int srvloop_gather_path_response(wired_srvloop* l, const u8* payload, usz len);
int srvloop_gather_ncid(wired_srvloop* l, const u8* payload, usz len);
int srvloop_gather_max_data(wired_srvloop* l, const u8* payload, usz len);
int srvloop_gather_max_stream_data(
    wired_srvloop* l, const u8* payload, usz len);
int  srvloop_gather_stream_closes(wired_srvloop* l, const u8* payload, usz len);
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
int srvloop_has_stream(const u8* payload, usz len);
int srvloop_feed_or_accept(wired_server* s, const u8* payload, usz len);
int dispatch_non_request(wired_server* s, const u8* payload, usz len);
int dispatch_gather_datagrams(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
int dispatch_gather_closes(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
int dispatch_gather_flowctl(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
int dispatch_gather_side_channels(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
int  srvloop_qdec_slot_find(const wired_srvloop* l, u64 id);
int  srvloop_qdec_stream_open(const wired_srvloop* l, u64 id);
void srvloop_reset_cancel_slot(wired_srvloop* l, int i, u64 code);

#endif
