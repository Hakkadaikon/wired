#ifndef APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_IMPL_H
#define APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_IMPL_H

/* Internal to the srvloop*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3settings/control_settings.h"
#include "app/http3/server/srvloop/dispatch.h"
#include "app/http3/server/srvloop/recv.h"
#include "app/http3/server/srvloop/respond.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "common/bytes/varint/varint.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/dispatch.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"
#include "transport/packet/header/packet/pnum.h"

#define WIRED_SRVLOOP_MAXPKTS \
  8 /* coalesced packets per datagram (RFC 9000 12.2) */

/* RFC 3168 ECN codepoints (matching mmsg_buf.ecn): 0 Not-ECT, 1 ECT(1),
 * 2 ECT(0), 3 CE. Indexes srvloop_ecn_counter_for below. */
#define WIRED_ECN_ECT1 1
#define WIRED_ECN_ECT0 2
#define WIRED_ECN_CE 3

/* The opened packet's level and its (still-mutable) bytes, as
 * srvloop_note_app_rx / srvloop_note_hs_rx need both together. */
typedef struct {
  int         level;
  wired_mspan pkt;
} srvloop_opened;

void srvloop_body_reset(wired_srvloop_stream_slot* slot);
void srvloop_body_rearm(wired_srvloop_stream_slot* slot);
void srvloop_streams_reset(wired_srvloop* l);
void srvloop_wt_window_reset(wired_srvloop_wt_window* w);
void srvloop_wt_streams_reset(wired_srvloop* l);
void srvloop_wt_uni_streams_reset(wired_srvloop* l);
void srvloop_pending_priority_reset(wired_srvloop* l);
void srvloop_init_pn(wired_srvloop* l);
void srvloop_init_req(wired_srvloop* l);
void srvloop_init_ecn(wired_srvloop* l);
void srvloop_init_seen(wired_srvloop* l);
u64* srvloop_ecn_counter_for(wired_srvloop* l, u8 ecn);
u64  srvloop_app_largest_pn(const wired_srvloop* l);
int  srvloop_app_pkt_is_long(u8 byte0);
void srvloop_note_app_rx(
    wired_srvloop* l, wired_server* s, const srvloop_opened* o);
u64  srvloop_hs_largest_pn(const wired_srvloop* l);
void srvloop_note_hs_rx(wired_srvloop* l, const srvloop_opened* o);
int  srvloop_stream_slot_find(const wired_srvloop* l, u64 stream_id);
int  srvloop_pending_priority_find(const wired_srvloop* l, u64 stream_id);
void srvloop_pending_priority_consume(wired_srvloop* l, usz i);
void srvloop_closed_shift64(wired_srvloop_closed* w, u64 k);
void srvloop_closed_advance(wired_srvloop_closed* w);
void srvloop_req_closed_mark(wired_srvloop* l, u64 stream_id);
int  srvloop_req_closed_has(const wired_srvloop* l, u64 stream_id);
int  srvloop_stream_slot_claim(wired_srvloop* l, u64 stream_id);
int  srvloop_wt_slot_claim_at(wired_srvloop* l, usz i, u64 stream_id);
void srvloop_wt_closed_mark(wired_srvloop* l, u64 stream_id);
usz  srvloop_wt_window_skip_stale(
    const wired_srvloop_wt_window* win, u64 abs_off, usz n);
void srvloop_wt_range_merge_into(
    wired_srvloop_wt_window* win, usz i, u64 lo, u64 hi);
int srvloop_wt_range_find_mergeable(
    const wired_srvloop_wt_window* win, u64 lo, u64 hi);
void srvloop_wt_ranges_sort(wired_srvloop_wt_window* win);
void srvloop_wt_window_recompute_frontier(wired_srvloop_wt_window* win);
void srvloop_wt_window_insert(wired_srvloop_wt_window* win, u64 lo, u64 hi);
int  srvloop_has_close(wired_span pl, u64* code);
void srvloop_collect_acks(wired_srvloop* l, wired_span pl);
void srvloop_note_ack_owed(
    pnspaces_recv* recv,
    int            space,
    ackpolicy*     policy,
    wired_span     pl,
    u64            pn,
    u64            now_ms);
void srvloop_step_dispatch(const wired_srvloop_conn* conn, wired_span payload);
void srvloop_step_note_ack_owed(
    wired_srvloop* l, wired_span payload, int level);
int  srvloop_step_dup(const wired_srvloop* l, int level);
void srvloop_step_opened(
    const wired_srvloop_conn*     conn,
    const wired_srvloop_recv_out* ro,
    wired_mspan                   pkt);
void srvloop_step_one(const wired_srvloop_conn* conn, wired_mspan pkt);
void srvloop_rearm_reqacc(wired_srvloop* l);
void srvloop_rearm_incomplete(wired_srvloop* l);
void srvloop_rearm_frame_unexpected(wired_srvloop* l);

#endif
