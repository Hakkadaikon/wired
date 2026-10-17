#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_upf_owner_ok(
    wired_moqt_hub*           hub,
    const wired_moqtrun_peer* op,
    const wired_wt_session*   s,
    moqtrun_key               k);
static int  moqtrun_upf_is_filter(u64 type);
static void moqtrun_upf_filters(const moqctl_params* in, moqctl_params* out);
static int  moqtrun_upf_enc22(wired_mspan buf, usz* off, const void* m);
static int  moqtrun_upf_enc19(wired_mspan buf, usz* off, const void* m);
static moqtrun_body_encode_fn moqtrun_upf_encoder(int ver);

/* ======= upstream FETCH (draft-22 3.2.3, 7.6, 9.11-9.12, 11.4, 12.1) =======
 * A FETCH or fill whose range starts with Locations the cache cannot
 * vouch for (never cached, evicted, or a gap the cache cannot rule out)
 * asks one matching publisher for them with one FETCH of its own: the
 * track's own publisher when it may be asked, else a session announcing a
 * covering namespace. The upstream answer owns the front of the range up
 * to the last such Location (the span; a Descending fetch: all of it),
 * the cache the rest; upstream items are relayed the moment they arrive,
 * in delivery order, never buffered. A FETCH of a track the hub does not
 * hold goes upstream whole and its FETCH_OK waits for the upstream one.
 * When the leg ends without covering its span -- an error, a reset, an
 * out-of-place item, a refused write, its budget -- the cache side takes
 * over at the cursor and reports what it lacks as unknown (or timed out).
 * Nothing relayed is cached (the cache assumes ascending arrival).
 * ponytail: no two FETCHes share an upstream one, and an upstream GOAWAY
 * on the request stream is not followed by a re-issue. */

/* No parameters: a fill carries no Range Filter of its own. */
const moqctl_params MOQTRUN_UPF_NO_PARAMS;

/* ----- choosing the publisher ----- */

/* The peer that publishes k (its PUBLISH, or the hub's upstream SUBSCRIBE
 * claimed it there), else 0. */
wired_moqtrun_peer* moqtrun_upf_owner(wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (moqtrun_peer_track_for_name(&hub->peers[i], k)) {
      return &hub->peers[i];
    }
  }
  return 0;
}

/* op may be asked for k on behalf of s: usable (no GOAWAY, not being
 * closed), not s itself, not already tried by a wait for a new path. */
static int moqtrun_upf_owner_ok(
    wired_moqt_hub*           hub,
    const wired_moqtrun_peer* op,
    const wired_wt_session*   s,
    moqtrun_key               k) {
  return moqtrun_up_peer_usable(op) && op->wt != s &&
         !(moqtrun_rp_skip(hub, k) & moqtrun_rp_bit(hub, op->wt));
}

/* draft-22 7.6: the publisher asked for k on behalf of s -- the track's
 * owner op when it may be, else a covering announcer -- or 0. */
wired_moqtrun_peer* moqtrun_upf_target(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     op,
    const wired_wt_session* s,
    moqtrun_key             k) {
  wired_moqtrun_req* a;
  if (moqtrun_upf_owner_ok(hub, op, s, k)) {
    return op;
  }
  a = moqtrun_up_announcer(hub, s, k);
  return a ? moqtrun_find_by_wt(hub, a->wt) : 0;
}

/* ----- the upstream FETCH ----- */

/* A Range Filter a FETCH may carry (draft-22 3.3.2). */
static int moqtrun_upf_is_filter(u64 type) {
  return type >= MOQCTL_PARAM_SUBGROUP_FILTER &&
         type <= MOQCTL_PARAM_OBJECT_PROPERTY_FILTER;
}

static void moqtrun_upf_filters(const moqctl_params* in, moqctl_params* out) {
  for (usz i = 0; i < in->n; i++) {
    if (moqtrun_upf_is_filter(in->items[i].type)) {
      out->items[out->n++] = in->items[i];
    }
  }
}

/* The upstream FETCH's parameters: the same Group Order, and the
 * downstream FETCH's Range Filters, byte for byte, where the upstream
 * draft has them (the publisher filters what it sends). */
void moqtrun_upf_params(
    const moqctl_params* in, int rngf, int desc, moqctl_params* out) {
  moqctl_param order = {0};
  order.type         = MOQCTL_PARAM_GROUP_ORDER;
  order.enc          = MOQCTL_PENC_UINT8;
  order.u8v          = 0x2;
  out->n             = 0;
  if (desc) {
    out->items[out->n++] = order;
  }
  if (rngf) {
    moqtrun_upf_filters(in, out);
  }
}

/* An inclusive end as a range end: a whole group (what the cache cannot
 * vouch for runs to its last Object), else that Object. */
void moqtrun_upf_rl_end(moqctl_rangeloc* rl, moqctl_loc e) {
  rl->end_group  = e.group;
  rl->end_object = e.object;
  rl->ek = e.object >= MOQCACHE_OBJ_ID_MAX ? MOQCTL_REK_GROUP : MOQCTL_REK_OBJ;
}

static int moqtrun_upf_enc22(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_req22_encode(buf, off, m);
}

static int moqtrun_upf_enc19(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_req19_encode(buf, off, m);
}

static moqtrun_body_encode_fn moqtrun_upf_encoder(int ver) {
  return (moqver_caps(ver) & MOQVER_CAP_FETCH_BODY_V22) ? moqtrun_upf_enc22
                                                        : moqtrun_upf_enc19;
}

/* m on a fresh request stream to pp under the hub's next odd Request ID
 * (written into m); the stream id, -1 when no stream opened or m has no
 * wire form in pp's draft. */
i64 moqtrun_upf_send(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, moqfetch_req* m) {
  u8 msg[WIRED_MOQTRUN_CTL_MSG_MAX + WIRED_MOQTRUN_CTL_HDR_MAX];
  m->request_id = pp->request_id_next;
  usz n         = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQFETCH_T_FETCH,
      moqtrun_upf_encoder(pp->ver), m);
  i64 sid = n ? hub->io.open_bidi_stream(pp->wt, wired_span_of(msg, n)) : -1;
  if (sid >= 0) {
    pp->request_id_next += 2;
  }
  return sid;
}
