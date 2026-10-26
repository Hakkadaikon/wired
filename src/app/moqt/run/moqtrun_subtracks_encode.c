#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_subtracks_encode_pub(
    wired_mspan buf, usz* off, const void* m);
static void moqtrun_subtracks_pub_fill(
    moqctl_publish*            m,
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    const wired_moqtrun_req*   q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st);
static void moqtrun_subtracks_pub_opened(
    wired_moqtrun_req*         q,
    i64                        sid,
    u64                        alias,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st);

static int moqtrun_subtracks_encode_pub(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_encode(buf, off, m);
}

/* The PUBLISH m for t on st_peer's session, naming q's request_id. */
static void moqtrun_subtracks_pub_fill(
    moqctl_publish*            m,
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    const wired_moqtrun_req*   q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st) {
  usz off        = 0;
  m->request_id  = q->request_id;
  m->track_alias = moqtrun_session_alias(hub, (usz)(st_peer - hub->peers), t);
  m->params      = moqtrun_subtracks_publish_params(st);
  moqctl_ns_take(wired_span_of(t->ns, t->ns_len), &off, &m->name.ns);
  m->name.name = wired_span_of(t->name, t->name_len);
  /* draft-18 9.6 / 2.5: the relayed track's Track Properties, unchanged */
  m->track_properties = moqtrun_track_props(t);
}

/* q once its PUBLISH for t went out on stream sid with alias. */
static void moqtrun_subtracks_pub_opened(
    wired_moqtrun_req*         q,
    i64                        sid,
    u64                        alias,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st) {
  q->stream_id     = (u64)sid;
  q->opened        = 1;
  q->kind          = MOQCTL_T_PUBLISH;
  q->pub_track_tag = t->cache_tag;
  q->pub_alias     = alias;
  q->has_forward   = st->has_forward;
  q->forward       = st->forward;
  q->group_order   = st->group_order;
  moqtrun_rngf_copy_objects(q, st);
}

/* Opens a fresh PUBLISH bidi stream on st_peer's session for t, naming q's
 * request_id and st_peer's session alias for t (10.9; draft-22 3.1.3,
 * moqtrun_session_alias), kept on q as pub_alias; 1 sent, 0 when the transport
 * has no bidi stream (or equivalent resource) to open -- the caller falls back
 * to PUBLISH_SKIPPED (1767-1771: "no available bidirectional streams or
 * any other reason"). */
int moqtrun_subtracks_open_pub(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    wired_moqtrun_req*         q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st) {
  u8
      msg[WIRED_MOQTRUN_CTL_HDR_MAX + WIRED_MOQTRUN_MAX_NS +
          WIRED_MOQTRUN_MAX_NAME + 32 + WIRED_MOQTRUN_TRACK_PROPS_MAX];
  moqctl_publish m = {0};
  moqtrun_subtracks_pub_fill(&m, hub, st_peer, q, t, st);
  usz n = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_PUBLISH,
      moqtrun_subtracks_encode_pub, &m);
  i64 sid = hub->io.open_bidi_stream(st_peer->wt, wired_span_of(msg, n));
  if (sid < 0) {
    return 0;
  }
  moqtrun_subtracks_pub_opened(q, sid, m.track_alias, t, st);
  return 1;
}

/* 10.20: Track Namespace Suffix (past st's own Prefix, like
 * moqtrun_disc_push's NAMESPACE) then Track Name, queued on st's own
 * stream -- no new stream, per the draft's own wording ("sends ... on the
 * SUBSCRIBE_TRACKS response stream"). */
int moqtrun_subtracks_encode_skip(wired_mspan buf, usz* off, const void* m) {
  return moqns_pub_skipped_encode(buf, off, m);
}

/* t's namespace fields past st's own Prefix (10.20's "Track Namespace
 * Suffix"), decoded straight into a moqctl_ns by re-counting the
 * remainder -- the suffix byte layout (Length-prefixed fields, no count
 * of its own here) is identical to a bare Track Namespace's own fields,
 * so moqctl_ns_take's Length-prefixed-field reader applies unchanged once
 * fed just the suffix's field count. */
void moqtrun_subtracks_ns_suffix(
    const wired_moqtrun_req* st, const wired_moqtrun_track* t, moqctl_ns* out) {
  u8         buf[WIRED_MOQTRUN_MAX_NS + 9];
  u64        pre_n, all_n;
  usz        put = 0, take = 0;
  wired_span pre = moqtrun_disc_fields(st, &pre_n);
  wired_span all =
      moqtrun_disc_fields_of(wired_span_of(t->ns, t->ns_len), &all_n);
  wired_span suf = wired_span_of(all.p + pre.n, all.n - pre.n);
  moqvi_put(wired_mspan_of(buf, sizeof buf), &put, all_n - pre_n);
  bytes_memcpy(buf + put, suf.p, suf.n);
  moqctl_ns_take(wired_span_of(buf, put + suf.n), &take, out);
}
