/* libFuzzer harness for the MoQT hub run loop (app/moqt/run, moqtrun.h):
 * the session runtime fuzz_moqt.c leaves out. One static hub, re-initialised
 * per input and configured like the shipped servers (examples/moqt_interop,
 * examples/moqt_chat/server), is driven through every entry point a
 * transport calls, with a stub wired_moqt_io underneath.
 *
 * Input: byte 0 = hub options (FZ_OPT_*), then up to FZ_MAX_OPS operations,
 * one opcode byte (% FZ_OP_COUNT) and its operands. A missing operand reads
 * as 0; a length is clamped to the bytes left.
 *
 * Every b operand names its peer in the low two bits: peer (b&3)%3.
 *
 *   0 OPEN    b            the peer joins; (b>>2)%6 picks its draft token
 *                          (moqt-23/22/19/18, none = legacy bidi, unlisted),
 *                          b&0x80 = raw QUIC (on_session_raw) else WT
 *   1 CLOSE   b            on_session_close
 *   2 STREAM  b sid len16 bytes   on_stream_data(stream sid, bytes,
 *                          fin = b>>7); sid's low 2 bits are the RFC 9000
 *                          2.1 stream type, so one byte reaches client
 *                          bidi/uni streams and the hub's own (stub ids)
 *   3 DGRAM   b len16 bytes       on_datagram(bytes)
 *   4 TICK    b            clock += b&0x7f ms (<<7 when b&0x80), then tick
 *   5 RESET   b sid        on_stream_reset(sid, mapped = b>>7)
 *   6 DRAIN   b            on_session_draining
 *   7 GOAWAY  b            wired_moqt_goaway(timeout b*16 ms, URI iff b&1)
 *   8 IO      m16          bit i of m set: stub io call i (FZ_IO_*) refuses
 *                          from now on -- the back-pressure paths
 *
 * Each delivery is handed to the hub in its own exact-size heap block,
 * freed on return: ASan then reports a read past the delivery or a view
 * kept beyond the call. The stubs read every payload the hub sends for the
 * same reason. Not covered: the transport underneath (srvrun/srvloop, QUIC
 * flow control and ACK timing) and an io table lacking optional callbacks.
 * Hosted build only, like fuzz_moqt.c. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app/moqt/cache/moqcache.c"
#include "app/moqt/cache/moqcache_evict.c"
#include "app/moqt/cache/moqcache_expire.c"
#include "app/moqt/cache/moqcache_item.c"
#include "app/moqt/cache/moqcache_rec.c"
#include "app/moqt/ctl/moqctl.c"
#include "app/moqt/ctl/moqctl_errdet.c"
#include "app/moqt/ctl/moqctl_errdet_put.c"
#include "app/moqt/ctl/moqctl_ftn.c"
#include "app/moqt/ctl/moqctl_goaway.c"
#include "app/moqt/ctl/moqctl_locfilter.c"
#include "app/moqt/ctl/moqctl_ns.c"
#include "app/moqt/ctl/moqctl_param.c"
#include "app/moqt/ctl/moqctl_param_take.c"
#include "app/moqt/ctl/moqctl_params.c"
#include "app/moqt/ctl/moqctl_pp.c"
#include "app/moqt/ctl/moqctl_publish.c"
#include "app/moqt/ctl/moqctl_pv.c"
#include "app/moqt/ctl/moqctl_rangefilter.c"
#include "app/moqt/ctl/moqctl_rangeloc19.c"
#include "app/moqt/ctl/moqctl_rangeloc22.c"
#include "app/moqt/ctl/moqctl_request.c"
#include "app/moqt/ctl/moqctl_rngf.c"
#include "app/moqt/ctl/moqctl_rngf_put.c"
#include "app/moqt/ctl/moqctl_setup.c"
#include "app/moqt/ctl/moqctl_ssa.c"
#include "app/moqt/ctl/moqctl_ssts.c"
#include "app/moqt/ctl/moqctl_subscribe.c"
#include "app/moqt/ctl/moqctl_token.c"
#include "app/moqt/ctl/moqctl_type.c"
#include "app/moqt/data/moqdata.c"
#include "app/moqt/data/moqdata_blob.c"
#include "app/moqt/data/moqdata_obj.c"
#include "app/moqt/data/moqdata_obj_head.c"
#include "app/moqt/data/moqdata_subhdr.c"
#include "app/moqt/dgram/moqdg.c"
#include "app/moqt/dgram/moqdg_put.c"
#include "app/moqt/dgram/moqdg_put2.c"
#include "app/moqt/fetch/moqfetch.c"
#include "app/moqt/fetch/moqfetch_eor.c"
#include "app/moqt/fetch/moqfetch_fill.c"
#include "app/moqt/fetch/moqfetch_obj.c"
#include "app/moqt/fetch/moqfetch_ok.c"
#include "app/moqt/fetch/moqfetch_ok23.c"
#include "app/moqt/fetch/moqfetch_put.c"
#include "app/moqt/fetch/moqfetch_put_eor.c"
#include "app/moqt/fetch/moqfetch_req.c"
#include "app/moqt/fetch/moqfetch_take.c"
#include "app/moqt/kvp/moqkvp.c"
#include "app/moqt/ns/moqns.c"
#include "app/moqt/qraw/moqraw.c"
#include "app/moqt/run/moqtrel.c"
#include "app/moqt/run/moqtrun.c"
#include "app/moqt/run/moqtrun_accept.c"
#include "app/moqt/run/moqtrun_alias.c"
#include "app/moqt/run/moqtrun_asm.c"
#include "app/moqt/run/moqtrun_asm_pool.c"
#include "app/moqt/run/moqtrun_bidi.c"
#include "app/moqt/run/moqtrun_ccode.c"
#include "app/moqt/run/moqtrun_ctl.c"
#include "app/moqt/run/moqtrun_cut.c"
#include "app/moqt/run/moqtrun_cut_round.c"
#include "app/moqt/run/moqtrun_decode.c"
#include "app/moqt/run/moqtrun_dg.c"
#include "app/moqt/run/moqtrun_disc.c"
#include "app/moqt/run/moqtrun_disc_mask.c"
#include "app/moqt/run/moqtrun_dispatch.c"
#include "app/moqt/run/moqtrun_dispatch_subscribe.c"
#include "app/moqt/run/moqtrun_done.c"
#include "app/moqt/run/moqtrun_drain.c"
#include "app/moqt/run/moqtrun_each.c"
#include "app/moqt/run/moqtrun_early.c"
#include "app/moqt/run/moqtrun_encode.c"
#include "app/moqt/run/moqtrun_fend.c"
#include "app/moqt/run/moqtrun_fetch.c"
#include "app/moqt/run/moqtrun_fetch_last.c"
#include "app/moqt/run/moqtrun_fetch_start.c"
#include "app/moqt/run/moqtrun_fetches.c"
#include "app/moqt/run/moqtrun_fill.c"
#include "app/moqt/run/moqtrun_fill_on.c"
#include "app/moqt/run/moqtrun_fill_wait.c"
#include "app/moqt/run/moqtrun_frag.c"
#include "app/moqt/run/moqtrun_fsel.c"
#include "app/moqt/run/moqtrun_fsel_fetch.c"
#include "app/moqt/run/moqtrun_fwin.c"
#include "app/moqt/run/moqtrun_goaway.c"
#include "app/moqt/run/moqtrun_gone.c"
#include "app/moqt/run/moqtrun_hold.c"
#include "app/moqt/run/moqtrun_hold_replay.c"
#include "app/moqt/run/moqtrun_hooks.c"
#include "app/moqt/run/moqtrun_hub.c"
#include "app/moqt/run/moqtrun_key.c"
#include "app/moqt/run/moqtrun_late.c"
#include "app/moqt/run/moqtrun_live.c"
#include "app/moqt/run/moqtrun_live_send.c"
#include "app/moqt/run/moqtrun_malformed.c"
#include "app/moqt/run/moqtrun_moqt.c"
#include "app/moqt/run/moqtrun_mpub.c"
#include "app/moqt/run/moqtrun_mpub_dd.c"
#include "app/moqt/run/moqtrun_newer.c"
#include "app/moqt/run/moqtrun_ngr.c"
#include "app/moqt/run/moqtrun_ofilt.c"
#include "app/moqt/run/moqtrun_ofilt_round.c"
#include "app/moqt/run/moqtrun_ofilt_sel.c"
#include "app/moqt/run/moqtrun_own.c"
#include "app/moqt/run/moqtrun_param.c"
#include "app/moqt/run/moqtrun_params.c"
#include "app/moqt/run/moqtrun_past.c"
#include "app/moqt/run/moqtrun_past_relay.c"
#include "app/moqt/run/moqtrun_peer.c"
#include "app/moqt/run/moqtrun_pre.c"
#include "app/moqt/run/moqtrun_pubdone.c"
#include "app/moqt/run/moqtrun_pubinit.c"
#include "app/moqt/run/moqtrun_pubst.c"
#include "app/moqt/run/moqtrun_pubst_move.c"
#include "app/moqt/run/moqtrun_pubupd.c"
#include "app/moqt/run/moqtrun_rdv.c"
#include "app/moqt/run/moqtrun_rdv_do.c"
#include "app/moqt/run/moqtrun_rdv_owned.c"
#include "app/moqt/run/moqtrun_rel.c"
#include "app/moqt/run/moqtrun_rel_late.c"
#include "app/moqt/run/moqtrun_rel_maybe.c"
#include "app/moqt/run/moqtrun_rel_replay.c"
#include "app/moqt/run/moqtrun_rel_round.c"
#include "app/moqt/run/moqtrun_rel_send.c"
#include "app/moqt/run/moqtrun_rel_tick.c"
#include "app/moqt/run/moqtrun_relay.c"
#include "app/moqt/run/moqtrun_relay_open.c"
#include "app/moqt/run/moqtrun_relay_shed.c"
#include "app/moqt/run/moqtrun_relay_stale.c"
#include "app/moqt/run/moqtrun_req.c"
#include "app/moqt/run/moqtrun_req_stream.c"
#include "app/moqt/run/moqtrun_reqs.c"
#include "app/moqt/run/moqtrun_reset.c"
#include "app/moqt/run/moqtrun_resolve.c"
#include "app/moqt/run/moqtrun_resume.c"
#include "app/moqt/run/moqtrun_rid.c"
#include "app/moqt/run/moqtrun_rid_win.c"
#include "app/moqt/run/moqtrun_rngf.c"
#include "app/moqt/run/moqtrun_route.c"
#include "app/moqt/run/moqtrun_row.c"
#include "app/moqt/run/moqtrun_rp.c"
#include "app/moqt/run/moqtrun_rx.c"
#include "app/moqt/run/moqtrun_sched.c"
#include "app/moqt/run/moqtrun_set.c"
#include "app/moqt/run/moqtrun_setup.c"
#include "app/moqt/run/moqtrun_sgfin.c"
#include "app/moqt/run/moqtrun_sgt.c"
#include "app/moqt/run/moqtrun_ssts.c"
#include "app/moqt/run/moqtrun_startobj.c"
#include "app/moqt/run/moqtrun_stream.c"
#include "app/moqt/run/moqtrun_sub.c"
#include "app/moqt/run/moqtrun_subscribe.c"
#include "app/moqt/run/moqtrun_subtracks.c"
#include "app/moqt/run/moqtrun_subtracks_encode.c"
#include "app/moqt/run/moqtrun_subtracks_sync.c"
#include "app/moqt/run/moqtrun_take.c"
#include "app/moqt/run/moqtrun_tprops.c"
#include "app/moqt/run/moqtrun_tprops_d23.c"
#include "app/moqt/run/moqtrun_track.c"
#include "app/moqt/run/moqtrun_tstat.c"
#include "app/moqt/run/moqtrun_up.c"
#include "app/moqt/run/moqtrun_up_announcer.c"
#include "app/moqt/run/moqtrun_up_fan.c"
#include "app/moqt/run/moqtrun_up_forget.c"
#include "app/moqt/run/moqtrun_up_of.c"
#include "app/moqt/run/moqtrun_up_on.c"
#include "app/moqt/run/moqtrun_up_rx.c"
#include "app/moqt/run/moqtrun_up_send.c"
#include "app/moqt/run/moqtrun_up_settle.c"
#include "app/moqt/run/moqtrun_upd.c"
#include "app/moqt/run/moqtrun_upd_is.c"
#include "app/moqt/run/moqtrun_upd_ns.c"
#include "app/moqt/run/moqtrun_upd_run.c"
#include "app/moqt/run/moqtrun_update.c"
#include "app/moqt/run/moqtrun_upf.c"
#include "app/moqt/run/moqtrun_upf_data.c"
#include "app/moqt/run/moqtrun_upf_end.c"
#include "app/moqt/run/moqtrun_upf_failed.c"
#include "app/moqt/run/moqtrun_upf_from.c"
#include "app/moqt/run/moqtrun_upf_io.c"
#include "app/moqt/run/moqtrun_upf_mal.c"
#include "app/moqt/run/moqtrun_upf_move.c"
#include "app/moqt/run/moqtrun_upf_no.c"
#include "app/moqt/run/moqtrun_upf_nt.c"
#include "app/moqt/run/moqtrun_upf_obj.c"
#include "app/moqt/run/moqtrun_upf_on.c"
#include "app/moqt/run/moqtrun_upf_rx.c"
#include "app/moqt/run/moqtrun_upf_small.c"
#include "app/moqt/run/moqtrun_upf_store.c"
#include "app/moqt/run/moqtrun_upf_tail.c"
#include "app/moqt/run/moqtssts_run.c"
#include "app/moqt/run/moqtssts_run_moqtss.c"
#include "app/moqt/run/moqtssts_run_moqtss_in.c"
#include "app/moqt/run/moqtssts_run_moqtss_on.c"
#include "app/moqt/run/moqtssts_run_moqtss_prime.c"
#include "app/moqt/run/moqtssts_run_moqtss_ring.c"
#include "app/moqt/run/moqtssts_run_moqtss_room.c"
#include "app/moqt/run/moqtssts_run_moqtss_tick.c"
#include "app/moqt/run/moqtssts_run_moqtss_view.c"
#include "app/moqt/run/moqtswitch.c"
#include "app/moqt/run/moqtswitch_moqtsw.c"
#include "app/moqt/run/moqtswitch_moqtsw_bound.c"
#include "app/moqt/run/moqtswitch_moqtsw_old.c"
#include "app/moqt/run/moqtswitch_moqtsw_soft.c"
#include "app/moqt/run/moqtswitch_moqtsw_step.c"
#include "app/moqt/run/moqtswitch_moqtsw_upd.c"
#include "app/moqt/sess/moqsess.c"
#include "app/moqt/ssts/moqssts.c"
#include "app/moqt/ssts/moqssts_bp.c"
#include "app/moqt/ssts/moqssts_spent.c"
#include "app/moqt/tstat/moqtstat.c"
#include "app/moqt/ver/moqver.c"
#include "app/moqt/vi/moqvi.c"
#include "common/bytes/text/text.c"

#define FZ_PEERS 3
#define FZ_MAX_OPS 256
/* A delivery is at most the transport's WT receive window: the hub's
 * scratch buffers are sized on it (wired_moqt_hub.relay_scratch). */
#define FZ_DELIVERY_MAX WIRED_SRVLOOP_WT_BUF_CAP

enum {
  FZ_OPT_MULTI_PUB   = 1 << 0, /* multi_publisher (moqt_interop) */
  FZ_OPT_NEWEST      = 1 << 1, /* newest_group_only (moqt_chat) */
  FZ_OPT_RELIABLE    = 1 << 2, /* reliable_alias_limit 4 (moqt_chat) */
  FZ_OPT_SWITCH_SSTS = 1 << 3, /* switch_track + SSTS (moqt_chat) */
  FZ_OPT_NO_CACHE    = 1 << 4, /* no Object cache attached */
  FZ_OPT_DENY        = 1 << 5, /* all three authorizers refuse */
  FZ_OPT_OWN_TRACKS  = 1 << 6, /* hub-owned blob and live tracks */
  FZ_OPT_NO_IMPL     = 1 << 7, /* no_implementation */
};

enum {
  FZ_IO_OPEN_BIDI,
  FZ_IO_SEND,
  FZ_IO_SEND_UNI,
  FZ_IO_OPEN_UNI,
  FZ_IO_FIN,
  FZ_IO_RESET,
  FZ_IO_SEND_UNI2,
  FZ_IO_DGRAM,
  FZ_IO_HOLD,
  FZ_IO_BUDGET, /* set: no session send credit, no rate estimate */
  FZ_IO_CLOSE,
  FZ_IO_REPLY_OPEN,
  FZ_IO_PRIORITY,
  FZ_IO_STOP,
  FZ_IO_SCHED,
  FZ_IO_INFLIGHT, /* set: every stream still has unacknowledged bytes */
};

enum {
  FZ_OP_OPEN,
  FZ_OP_CLOSE,
  FZ_OP_STREAM,
  FZ_OP_DGRAM,
  FZ_OP_TICK,
  FZ_OP_RESET,
  FZ_OP_DRAIN,
  FZ_OP_GOAWAY,
  FZ_OP_IO,
  FZ_OP_COUNT,
};

static wired_moqt_hub g_hub;
static u8             g_arena[1u << 20]; /* the examples' cache size */
static unsigned       g_refuse;          /* FZ_OP_IO's mask */
static u64            g_streams;         /* streams the stubs opened */
static u64            g_now;             /* the tick clock, ms */
static u8             g_sink;

/* ===================== stub transport ===================== */

static int fz_ok(int call) { return !(g_refuse >> call & 1); }

/* Reads all of s, so ASan checks the view the hub handed out. */
static void fz_touch(wired_span s) {
  u8 x = 0;
  for (usz i = 0; i < s.n; i++) {
    x ^= s.p[i];
  }
  g_sink ^= x;
}

/* The next server-initiated stream id of the given RFC 9000 2.1 type
 * (1 = bidi, 3 = uni), or -1 when the call is refused. */
static i64 fz_open(int call, u64 type, wired_span payload) {
  fz_touch(payload);
  return fz_ok(call) ? (i64)(g_streams++ << 2 | type) : -1;
}

static int fz_sent(int call, wired_span payload) {
  fz_touch(payload);
  return fz_ok(call);
}

static i64 fz_open_bidi_stream(wired_wt_session* s, wired_span payload) {
  (void)s;
  return fz_open(FZ_IO_OPEN_BIDI, 1, payload);
}

static int fz_stream_send(
    wired_wt_session* s, u64 stream_id, wired_span payload, int fin) {
  (void)s, (void)stream_id, (void)fin;
  return fz_sent(FZ_IO_SEND, payload);
}

static i64 fz_send_uni(wired_wt_session* s, wired_span payload) {
  (void)s;
  return fz_open(FZ_IO_SEND_UNI, 3, payload);
}

static i64 fz_open_uni_stream(wired_wt_session* s, wired_span payload) {
  (void)s;
  return fz_open(FZ_IO_OPEN_UNI, 3, payload);
}

static int fz_stream_fin(wired_wt_session* s, u64 stream_id) {
  (void)s, (void)stream_id;
  return fz_ok(FZ_IO_FIN);
}

static int fz_stream_reset(wired_wt_session* s, u64 stream_id, u32 code) {
  (void)s, (void)stream_id, (void)code;
  return fz_ok(FZ_IO_RESET);
}

static i64 fz_send_uni2(wired_wt_session* s, wired_span head, wired_span body) {
  (void)s;
  fz_touch(head);
  return fz_open(FZ_IO_SEND_UNI2, 3, body);
}

static int fz_send_datagram(wired_wt_session* s, wired_span payload) {
  (void)s;
  return fz_sent(FZ_IO_DGRAM, payload);
}

static int fz_stream_hold(wired_wt_session* s, u64 stream_id, int hold) {
  (void)s, (void)stream_id, (void)hold;
  return fz_ok(FZ_IO_HOLD);
}

static usz fz_send_budget(wired_wt_session* s) {
  (void)s;
  return fz_ok(FZ_IO_BUDGET) ? (usz)-1 : 0;
}

static int fz_close_session(wired_wt_session* s, u32 code, wired_span reason) {
  (void)s, (void)code;
  return fz_sent(FZ_IO_CLOSE, reason);
}

static int fz_stream_reply_open(
    wired_wt_session* s, u64 stream_id, wired_span payload) {
  (void)s, (void)stream_id;
  return fz_sent(FZ_IO_REPLY_OPEN, payload);
}

static int fz_stream_priority(wired_wt_session* s, u64 stream_id, u8 urgency) {
  (void)s, (void)stream_id, (void)urgency;
  return fz_ok(FZ_IO_PRIORITY);
}

static int fz_stream_stop(wired_wt_session* s, u64 stream_id, u32 code) {
  (void)s, (void)stream_id, (void)code;
  return fz_ok(FZ_IO_STOP);
}

static u64 fz_est_kbps(wired_wt_session* s) {
  (void)s;
  return fz_ok(FZ_IO_BUDGET) ? 2000 : 0;
}

static int fz_stream_sched(
    wired_wt_session* s, u64 stream_id, const wired_wt_sched* k) {
  (void)s, (void)stream_id;
  g_sink ^= *(const u8*)k;
  return fz_ok(FZ_IO_SCHED);
}

static int fz_stream_inflight(wired_wt_session* s, u64 stream_id) {
  (void)s, (void)stream_id;
  return !fz_ok(FZ_IO_INFLIGHT);
}

/* Every callback set, as wired_moqraw_io plus moqt_chat's send_uni2. */
static wired_moqt_io fz_io(void) {
  return (wired_moqt_io){
      .open_bidi_stream  = fz_open_bidi_stream,
      .stream_send       = fz_stream_send,
      .send_uni          = fz_send_uni,
      .open_uni_stream   = fz_open_uni_stream,
      .stream_fin        = fz_stream_fin,
      .stream_reset      = fz_stream_reset,
      .send_uni2         = fz_send_uni2,
      .send_datagram     = fz_send_datagram,
      .stream_hold       = fz_stream_hold,
      .send_budget       = fz_send_budget,
      .close_session     = fz_close_session,
      .stream_reply_open = fz_stream_reply_open,
      .stream_priority   = fz_stream_priority,
      .stream_stop       = fz_stream_stop,
      .est_kbps          = fz_est_kbps,
      .stream_sched      = fz_stream_sched,
      .stream_inflight   = fz_stream_inflight,
  };
}

/* ===================== hub configuration ===================== */

static int fz_deny(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_ftn*   name,
    const moqctl_token* tok) {
  (void)ctx, (void)s, (void)name, (void)tok;
  return 0;
}

static int fz_deny_ns(
    void*               ctx,
    wired_wt_session*   s,
    u64                 msg_type,
    const moqctl_ns*    ns,
    const moqctl_token* tok) {
  (void)ctx, (void)s, (void)msg_type, (void)ns, (void)tok;
  return 0;
}

/* The hub's own tracks: a static blob (alias 2) and a two-fragment live
 * track (alias 3, 10 ms Groups). */
static void fz_own_tracks(void) {
  static const u8         blob[40] = {1, 2, 3};
  static u8               wire[MOQDATA_BLOB_WIRE_CAP(sizeof blob)];
  static const wired_span frags[2] = {{blob, 7}, {blob + 7, 9}};
  wired_moqt_publish_blob(
      &g_hub, wired_span_of((const u8*)"movie", 5), 2,
      wired_span_of(blob, sizeof blob), wired_mspan_of(wire, sizeof wire));
  wired_moqt_publish_live(
      &g_hub, wired_span_of((const u8*)"live", 4), 3, frags, 2, 10, 0);
}

static void fz_hub_init(unsigned opts) {
  static const u64 algs[] = {
      MOQCTL_SSTS_ALG_BACKPRESSURE, MOQCTL_SSTS_ALG_DEFAULT};
  g_refuse  = 0;
  g_streams = 0;
  g_now     = 0;
  wired_moqt_init(&g_hub, fz_io());
  g_hub.multi_publisher      = (opts & FZ_OPT_MULTI_PUB) != 0;
  g_hub.newest_group_only    = (opts & FZ_OPT_NEWEST) != 0;
  g_hub.reliable_alias_limit = opts & FZ_OPT_RELIABLE ? 4 : 0;
  g_hub.no_implementation    = (opts & FZ_OPT_NO_IMPL) != 0;
  if (opts & FZ_OPT_SWITCH_SSTS) {
    g_hub.switch_track = 1;
    g_hub.ssts_algs    = algs;
    g_hub.ssts_alg_n   = sizeof algs / sizeof algs[0];
  }
  if (!(opts & FZ_OPT_NO_CACHE)) {
    wired_moqt_cache_attach(&g_hub, g_arena, sizeof g_arena);
  }
  if (opts & FZ_OPT_DENY) {
    g_hub.authorize_subscribe = fz_deny;
    g_hub.authorize_publish   = fz_deny;
    g_hub.authorize_namespace = fz_deny_ns;
  }
  if (opts & FZ_OPT_OWN_TRACKS) {
    fz_own_tracks();
  }
}

/* ===================== input ===================== */

typedef struct {
  const u8* p;
  usz       n;
} fz_in;

static unsigned fz_u8(fz_in* in) {
  if (in->n == 0) {
    return 0;
  }
  in->n--;
  return *in->p++;
}

/* A 16-bit little-endian length and that many bytes (clamped to what is
 * left and to FZ_DELIVERY_MAX), copied into an exact-size heap block the
 * caller frees. */
static wired_span fz_delivery(fz_in* in) {
  usz n = fz_u8(in);
  n |= (usz)fz_u8(in) << 8;
  n       = n < in->n ? n : in->n;
  n       = n < FZ_DELIVERY_MAX ? n : FZ_DELIVERY_MAX;
  u8* buf = malloc(n ? n : 1);
  if (!buf) {
    abort();
  }
  memcpy(buf, in->p, n);
  in->p += n;
  in->n -= n;
  return wired_span_of(buf, n);
}

/* Three fixed fake session identities; the hub only compares them. */
static wired_wt_session* fz_peer(unsigned b) {
  return (wired_wt_session*)(uintptr_t)(0x1000 * ((b & 3) % FZ_PEERS + 1));
}

/* ===================== operations ===================== */

static void fz_op_open(unsigned b) {
  static const char* const tok[] = {"moqt-23", "moqt-22", "moqt-19",
                                    "moqt-18", "",        "x"};
  const char*              t     = tok[(b >> 2) % 6];
  wired_span               proto = wired_span_of((const u8*)t, strlen(t));
  if (b & 0x80) {
    wired_moqt_on_session_raw(&g_hub, fz_peer(b), proto);
  } else {
    wired_moqt_on_session(&g_hub, fz_peer(b), wired_span_of(0, 0), proto);
  }
}

static void fz_op_stream(fz_in* in) {
  unsigned   b   = fz_u8(in);
  u64        sid = fz_u8(in);
  wired_span d   = fz_delivery(in);
  wired_moqt_on_stream_data(&g_hub, fz_peer(b), sid, d, b >> 7);
  free((void*)d.p);
}

static void fz_op_dgram(fz_in* in) {
  unsigned   b = fz_u8(in);
  wired_span d = fz_delivery(in);
  wired_moqt_on_datagram(&g_hub, fz_peer(b), d);
  free((void*)d.p);
}

static void fz_op_tick(unsigned b) {
  g_now += (u64)(b & 0x7f) << (b & 0x80 ? 7 : 0);
  wired_moqt_tick(&g_hub, g_now);
}

static void fz_op_reset(fz_in* in) {
  unsigned b = fz_u8(in);
  wired_moqt_on_stream_reset(&g_hub, fz_peer(b), fz_u8(in), b >> 7, 0);
}

static void fz_op_goaway(unsigned b) {
  const char* uri = b & 1 ? "https://example.test/moq" : "";
  wired_moqt_goaway(
      &g_hub, wired_span_of((const u8*)uri, strlen(uri)), (u64)b * 16);
}

static void fz_op_io(fz_in* in) {
  g_refuse = fz_u8(in);
  g_refuse |= fz_u8(in) << 8;
}

static void fz_op(fz_in* in) {
  switch (fz_u8(in) % FZ_OP_COUNT) {
    case FZ_OP_OPEN:
      fz_op_open(fz_u8(in));
      break;
    case FZ_OP_CLOSE:
      wired_moqt_on_session_close(&g_hub, fz_peer(fz_u8(in)));
      break;
    case FZ_OP_STREAM:
      fz_op_stream(in);
      break;
    case FZ_OP_DGRAM:
      fz_op_dgram(in);
      break;
    case FZ_OP_TICK:
      fz_op_tick(fz_u8(in));
      break;
    case FZ_OP_RESET:
      fz_op_reset(in);
      break;
    case FZ_OP_DRAIN:
      wired_moqt_on_session_draining(&g_hub, fz_peer(fz_u8(in)));
      break;
    case FZ_OP_GOAWAY:
      fz_op_goaway(fz_u8(in));
      break;
    default:
      fz_op_io(in);
      break;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) {
    return 0;
  }
  fz_in in = {(const u8*)data + 1, (usz)size - 1};
  fz_hub_init(data[0]);
  for (int i = 0; i < FZ_MAX_OPS && in.n > 0; i++) {
    fz_op(&in);
  }
  return 0;
}
