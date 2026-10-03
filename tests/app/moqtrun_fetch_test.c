/* Hub Object cache and FETCH (draft-ietf-moq-transport-19 10.12,
 * 10.13, 11.4.4). Real FETCH / SUBGROUP bytes go through the hub's
 * stream entry points; replies and fetch streams are read back from the
 * recording io stubs of moqtrun_test.c (same unity TU), reusing the
 * fixtures of moqtrun_sub_test.c. A "budget" of B bytes is an arena of B
 * payload bytes plus one MOQCACHE_HDR per record that has to fit. */

#define MF_ALIAS 1
#define MF_REQ 400 /* client bidi streams are 0 mod 4 (RFC 9000 2.1) */

static u8  mf_arena[64 * (MOQCACHE_HDR + 16)];
static u64 mf_pub_sid;
static u64 mf_ctrl_a;
static u64 mf_ctrl_b;

static moqctl_ftn mf_track(void) { return mtst_ftn("chat", "room1", "alice"); }

/* A publishes alice; B joins. cap 0 leaves the cache unattached. */
static void mf_init(usz cap) {
  moqctl_ftn f = mf_track();
  mtst_init();
  if (cap) wired_moqt_cache_attach(&mtst_hub, mf_arena, cap);
  mf_pub_sid = 2; /* client uni streams are 2 mod 4 */
  mf_ctrl_a  = mtst_join(SESS_A);
  mf_ctrl_b  = mtst_join(SESS_B);
  mtst_publish(SESS_A, mf_ctrl_a, &f, MF_ALIAS);
}

/* A opens a new stream carrying Object {g, o} of n bytes (each 16*g+o),
 * with FIN when fin; returns the stream id. */
static u64 mf_obj_on(u64 g, u64 o, usz n, int fin) {
  u8             buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u8             pl[MOQTRUN_TEST_MAX_PAYLOAD];
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x30; /* mode 0b00, no properties, default priority */
  h.track_alias      = MF_ALIAS;
  h.group_id         = g;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  for (usz i = 0; i < n; i++) pl[i] = (u8)(16 * g + o);
  moqdata_obj_put(
      wired_mspan_of(buf, sizeof buf), &off, o, wired_span_of(pl, n));
  mf_pub_sid += 4;
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, mf_pub_sid, wired_span_of(buf, off), fin);
  return mf_pub_sid;
}

/* A sends Object {g, o} of n bytes on its own one-shot stream. */
static void mf_obj(u64 g, u64 o, usz n) { mf_obj_on(g, o, n, 1); }

/* ===================== cache attach ===================== */

/* Whole Objects a publisher sends land in the attached arena. */
static void test_moqtrun_fetch_cache_attach(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 2);
  CHECK(mtst_hub.cache.used == MOQCACHE_HDR + 2);
}

/* Default: nothing attached, nothing cached. */
static void test_moqtrun_fetch_cache_default_off(void) {
  mf_init(0);
  mf_obj(0, 0, 2);
  CHECK(mtst_hub.cache.used == 0);
}

/* The publisher leaving releases its track's Objects. */
static void test_moqtrun_fetch_cache_released_on_leave(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 2);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mtst_hub.cache.used == 0);
}

/* A new PUBLISH of the name starts a new incarnation: the old Objects
 * go. */
static void test_moqtrun_fetch_cache_released_on_republish(void) {
  moqctl_ftn f = mf_track();
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 2);
  mtst_publish(SESS_A, mf_ctrl_a, &f, MF_ALIAS);
  CHECK(mtst_hub.cache.used == 0);
}

/* ===================== FETCH plumbing ===================== */

static u64 mf_req_sid; /* last request stream used */

static int mf_enc_fetch(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_fetch_encode(buf, off, m);
}

/* B sends m on a fresh request stream. */
static void mf_send_fetch(moqfetch_fetch* m) {
  u8  buf[MTST_MSG_MAX];
  usz n;
  mf_req_sid    = mf_req_sid < MF_REQ ? MF_REQ : mf_req_sid + 4;
  m->request_id = mf_req_sid; /* any even id; unique per request */
  n             = moqtrun_envelope_put(
      wired_mspan_of(buf, sizeof buf), MOQFETCH_T_FETCH, mf_enc_fetch, m);
  CHECK(n != 0);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_B, mf_req_sid, wired_span_of(buf, n), 0);
}

static void mf_standalone(moqctl_loc start, moqctl_loc end) {
  static moqfetch_fetch m;
  m.fetch_type = MOQFETCH_STANDALONE;
  m.track      = mf_track();
  m.start      = start;
  m.end        = end;
  m.params.n   = 0;
  mf_send_fetch(&m);
}

/* The reply on the last request stream: its Type; *code the
 * REQUEST_ERROR code, *end the FETCH_OK End Location. */
static u64 mf_reply(u64* code, moqctl_loc* end) {
  for (usz i = g_n_calls; i-- > 0;) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0, boff = 0;
    u64                      type = 0;
    wired_span               body;
    moqfetch_ok              ok;
    moqctl_request_error     e;
    if (c->kind != 12 || c->stream_id != mf_req_sid) continue;
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type == MOQFETCH_T_FETCH_OK &&
        moqfetch_ok_take(MOQVER_D19, body, &ok) == MOQCTL_OK)
      *end = ok.end;
    if (type == MOQCTL_T_REQUEST_ERROR &&
        moqctl_request_error_take(body, &boff, &e) == MOQCTL_OK)
      *code = e.error_code;
    return type;
  }
  return 0;
}

static u64 mf_error(void) {
  u64        code = ~(u64)0;
  moqctl_loc end;
  CHECK(mf_reply(&code, &end) == MOQCTL_T_REQUEST_ERROR);
  return code;
}

static moqctl_loc mf_ok_end(void) {
  u64        code;
  moqctl_loc end = {~(u64)0, 0};
  CHECK(mf_reply(&code, &end) == MOQFETCH_T_FETCH_OK);
  return end;
}

/* One decoded fetch-stream item. */
typedef struct {
  u64 flags;
  u64 group;
  u64 object;
  usz n;
  u8  first;
} mf_item;

static mf_item mf_items[32];
static usz     mf_n;
static int     mf_fin;
static u64     mf_hdr_rid;

static void mf_append(u8* buf, usz* len, const moqtrun_test_call* c) {
  for (usz i = 0; i < c->payload_len; i++) buf[(*len)++] = c->payload[i];
}

/* 1 iff c opens a fetch stream (FETCH_HEADER Type 0x5) to SESS_B. */
static int mf_opens(const moqtrun_test_call* c) {
  return c->s == SESS_B && (c->kind == 5 || c->kind == 4) && c->payload_len &&
         c->payload[0] == MOQDATA_TYPE_FETCH_HEADER;
}

/* Reassembles the accepted rounds of B's last fetch stream. */
static usz mf_gather(u8* buf) {
  usz len = 0;
  u64 sid = ~(u64)0;
  mf_fin  = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    if (mf_opens(c)) {
      sid = c->stream_id;
      len = 0;
      mf_append(buf, &len, c);
      mf_fin = c->kind == 4;
    } else if (c->kind == 3 && c->stream_id == sid && !c->refused) {
      mf_append(buf, &len, c);
      mf_fin = c->fin;
    }
  }
  return len;
}

/* Decodes B's last fetch stream into mf_items; 0 on a decode error. */
static int mf_read(void) {
  static u8    buf[4096];
  usz          len = mf_gather(buf), off = 0;
  moqfetch_seq seq = {0};
  mf_n             = 0;
  if (moqfetch_hdr_take(wired_span_of(buf, len), &off, &mf_hdr_rid) !=
      MOQCTL_OK)
    return 0;
  while (off < len && mf_n < 32) {
    moqfetch_obj o;
    if (moqfetch_obj_take(wired_span_of(buf, len), &off, &seq, &o) != MOQCTL_OK)
      return 0;
    mf_items[mf_n].flags  = o.flags;
    mf_items[mf_n].group  = o.group;
    mf_items[mf_n].object = o.object;
    mf_items[mf_n].n      = o.payload.n;
    mf_items[mf_n].first  = o.payload.n ? o.payload.p[0] : 0;
    mf_n++;
  }
  return 1;
}

static int mf_is_obj(usz i, u64 g, u64 o, usz n) {
  return i < mf_n && mf_items[i].flags < 0x80 && mf_items[i].group == g &&
         mf_items[i].object == o && mf_items[i].n == n &&
         mf_items[i].first == (u8)(16 * g + o);
}

static int mf_is_unknown(usz i, u64 g, u64 o) {
  return i < mf_n && mf_items[i].flags == MOQFETCH_EOR_UNKNOWN &&
         mf_items[i].group == g && mf_items[i].object == o;
}

static moqctl_loc mf_loc(u64 g, u64 o) {
  moqctl_loc l = {g, o};
  return l;
}

static int mf_loc_eq(moqctl_loc a, u64 g, u64 o) {
  return a.group == g && a.object == o;
}

/* ===================== standalone FETCH ===================== */

/* Nothing published -> INVALID_RANGE (10.12.3). */
static void test_moqtrun_fetch_nothing_published(void) {
  mf_init(sizeof mf_arena);
  mf_standalone(mf_loc(0, 0), mf_loc(0, 1));
  CHECK(mf_error() == MOQCTL_ERR_INVALID_RANGE);
}

/* Start past Largest -> INVALID_RANGE; End past Largest is cut
 * to {Largest.Group, Largest.Object + 1} in FETCH_OK (10.13). */
static void test_moqtrun_fetch_range_against_largest(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_standalone(mf_loc(1, 0), mf_loc(1, 1));
  CHECK(mf_error() == MOQCTL_ERR_INVALID_RANGE);
  mf_standalone(mf_loc(0, 0), mf_loc(2, 0));
  CHECK(mf_loc_eq(mf_ok_end(), 0, 2));
}

/* End not past Start (10.12.3: End MUST be >= Start) -> INVALID_RANGE;
 * End {g, 0} is the whole group g, so it is past Start {g, 0}. */
static void test_moqtrun_fetch_end_before_start(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_standalone(mf_loc(0, 1), mf_loc(0, 1));
  CHECK(mf_error() == MOQCTL_ERR_INVALID_RANGE);
  mf_standalone(mf_loc(0, 0), mf_loc(0, 0));
  CHECK(mf_loc_eq(mf_ok_end(), 0, 2));
}

/* A track nobody publishes -> DOES_NOT_EXIST. */
static void test_moqtrun_fetch_unknown_track(void) {
  static moqfetch_fetch m;
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  m.fetch_type = MOQFETCH_STANDALONE;
  m.track      = mtst_ftn("chat", "room1", "nobody");
  m.end        = mf_loc(0, 1);
  mf_send_fetch(&m);
  CHECK(mf_error() == MOQCTL_ERR_DOES_NOT_EXIST);
}

/* Cached Objects arrive with their payload on a FETCH_HEADER
 * stream naming the request, the last one carrying FIN. */
static void test_moqtrun_fetch_serves_cached(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 3);
  mf_obj(0, 1, 2);
  mf_standalone(mf_loc(0, 0), mf_loc(0, 2));
  CHECK(mf_loc_eq(mf_ok_end(), 0, 2));
  CHECK(mf_read());
  CHECK(mf_hdr_rid == mf_req_sid);
  CHECK(mf_n == 2);
  CHECK(mf_is_obj(0, 0, 0, 3) && mf_is_obj(1, 0, 1, 2));
  CHECK(mf_fin);
}

/* No arena: the whole range is one unknown range, then FIN. */
static void test_moqtrun_fetch_no_cache_unknown(void) {
  mf_init(0);
  mf_obj(0, 0, 1);
  mf_standalone(mf_loc(0, 0), mf_loc(0, 1));
  CHECK(mf_read());
  CHECK(mf_n == 1 && mf_is_unknown(0, 0, 0));
  CHECK(mf_fin);
}

/* An evicted group 0 is one unknown range, then group 1's Objects
 * once each, ascending, FIN last. */
static void test_moqtrun_fetch_evicted_group_unknown(void) {
  mf_init(2 * (MOQCACHE_HDR + 1));
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_obj(1, 1, 1);
  mf_standalone(mf_loc(0, 0), mf_loc(2, 0));
  CHECK(mf_loc_eq(mf_ok_end(), 1, 2));
  CHECK(mf_read());
  CHECK(mf_n == 3);
  CHECK(mf_is_unknown(0, 0, MOQCACHE_OBJ_ID_MAX));
  CHECK(mf_is_obj(1, 1, 0, 1) && mf_is_obj(2, 1, 1, 1));
  CHECK(mf_fin);
}

/* A refused round keeps the cursor on (0,1); group 0 evicted
 * meanwhile turns it into an unknown range, never stale bytes, and group
 * 1 follows. */
static void test_moqtrun_fetch_eviction_under_cursor(void) {
  mf_init(4 * (MOQCACHE_HDR + 1));
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_obj(1, 1, 1);
  g_stream_send_ok_n = 1;
  mf_standalone(mf_loc(0, 0), mf_loc(1, 2));
  mf_obj(2, 0, 1); /* evicts group 0 */
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mf_read());
  CHECK(mf_n == 4);
  CHECK(mf_is_obj(0, 0, 0, 1));
  CHECK(mf_is_unknown(1, 0, MOQCACHE_OBJ_ID_MAX));
  CHECK(mf_is_obj(2, 1, 0, 1) && mf_is_obj(3, 1, 1, 1));
  CHECK(mf_fin);
}

/* The open group dropped for overflowing the budget under the
 * cursor reads as unknown. */
static void test_moqtrun_fetch_oversize_under_cursor(void) {
  mf_init(2 * MOQCACHE_HDR + 3);
  mf_obj(1, 0, 2);
  g_stream_send_ok_n = 0;
  mf_standalone(mf_loc(1, 0), mf_loc(1, 1));
  mf_obj(1, 1, 2);
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mf_read());
  CHECK(mf_n == 1 && mf_is_unknown(0, 1, 0));
  CHECK(mf_fin);
}

/* The publisher leaving mid-FETCH releases the cache; the rest
 * is unknown and the stream still FINs. */
static void test_moqtrun_fetch_publisher_leaves(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  g_stream_send_ok_n = 1;
  mf_standalone(mf_loc(0, 0), mf_loc(0, 2));
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mtst_hub.cache.used == 0);
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mf_read());
  CHECK(mf_n == 2);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_unknown(1, 0, 1));
  CHECK(mf_fin);
}

/* The requester's session closing ends its fetches: nothing more is
 * sent for them. */
static void test_moqtrun_fetch_requester_leaves(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_stream_send_ok_n = 0;
  mf_standalone(mf_loc(0, 0), mf_loc(0, 1));
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  g_stream_send_ok_n = -1;
  usz before         = g_n_calls;
  wired_moqt_tick(&mtst_hub, 1);
  for (usz i = before; i < g_n_calls; i++) CHECK(g_calls[i].s != SESS_B);
}

/* 1 iff no fetch slot is in use. */
static int mf_no_fetch(void) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (mtst_hub.fetches[i].in_use) return 0;
  return 1;
}

/* B's fetch data stream id (its FETCH_HEADER open). */
static u64 mf_data_sid(void) {
  for (usz i = g_n_calls; i-- > 0;)
    if (mf_opens(&g_calls[i])) return g_calls[i].stream_id;
  return ~(u64)0;
}

/* 1 iff the hub reset stream sid toward B. */
static int mf_reset_sent(u64 sid) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 7 && g_calls[i].stream_id == sid) return 1;
  return 0;
}

/* Starts a FETCH whose rounds the transport refuses. */
static u64 mf_stuck_fetch(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_stream_send_ok_n = 0;
  mf_standalone(mf_loc(0, 0), mf_loc(0, 1));
  CHECK(!mf_no_fetch());
  return mf_data_sid();
}

/* Resetting the FETCH request stream cancels the fetch (3.3.3): its data
 * stream is reset and its slot freed, nothing more is sent. */
static void test_moqtrun_fetch_cancelled_by_request_reset(void) {
  u64 sid = mf_stuck_fetch();
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, mf_req_sid, 0, 0);
  CHECK(mf_reset_sent(sid));
  CHECK(mf_no_fetch());
  g_stream_send_ok_n = -1;
  usz before         = g_n_calls;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(g_n_calls == before);
}

/* STOP_SENDING on the fetch data stream frees the slot. */
static void test_moqtrun_fetch_data_stream_stopped(void) {
  u64 sid = mf_stuck_fetch();
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, sid, 0, 0);
  CHECK(mf_no_fetch());
}

/* A fetch refused for longer than WIRED_MOQTREL_STALL_MS is given up:
 * its data stream is reset and its slot freed. */
static void test_moqtrun_fetch_stall_gives_up(void) {
  u64 sid = mf_stuck_fetch();
  wired_moqt_tick(&mtst_hub, WIRED_MOQTREL_STALL_MS);
  CHECK(!mf_no_fetch());
  wired_moqt_tick(&mtst_hub, WIRED_MOQTREL_STALL_MS + 1);
  CHECK(mf_reset_sent(sid));
  CHECK(mf_no_fetch());
}

/* ===================== joining FETCH ===================== */

static u64 mf_sub_rid;

/* B SUBSCRIBEs to alice (filter Largest Object unless params says
 * otherwise); returns the SUBSCRIBE's Request ID. */
static u64 mf_subscribe(const moqctl_params* params) {
  moqctl_ftn    f  = mf_track();
  moqctl_params lo = mtst_params_filter(MOQCTL_FILTER_LARGEST);
  mf_sub_rid += 2;
  mtst_subscribe_p(SESS_B, mf_ctrl_b, &f, mf_sub_rid, params ? params : &lo);
  return mf_sub_rid;
}

static void mf_joining(u64 type, u64 joining_rid, u64 joining_start) {
  static moqfetch_fetch m;
  m.fetch_type         = type;
  m.joining_request_id = joining_rid;
  m.joining_start      = joining_start;
  m.params.n           = 0;
  mf_send_fetch(&m);
}

/* The Location of the last Object relayed to B on a SUBGROUP stream. */
static int mf_relayed(u64 g, u64 o) {
  const moqtrun_test_call* c   = moqtrun_test_last_kind(4);
  usz                      off = 0;
  moqdata_subhdr           h;
  moqdata_obj              obj;
  if (!c || c->s != SESS_B) return 0;
  wired_span w = wired_span_of(c->payload, c->payload_len);
  if (moqdata_subhdr_take(w, &off, &h) != MOQDATA_OK) return 0;
  moqdata_objseq seq = moqdata_objseq_of(h.type);
  if (moqdata_obj_take(w, &off, &seq, &obj) != MOQDATA_OK) return 0;
  return h.group_id == g && obj.object_id == o;
}

/* SUBSCRIBE (Largest Object) at Largest {1,0} starts at (1,1);
 * the relative joining FETCH covers (0,0)..(1,0) and FINs; the next
 * Object reaches B through the subscription -- each Location once. */
static void test_moqtrun_fetch_relative_join_no_gap(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  u64 rid = mf_subscribe(0);
  CHECK(mf_loc_eq(mtst_largest()->loc, 1, 0));
  CHECK(mf_loc_eq(mtst_sub(SESS_A, SESS_B)->start, 1, 1));
  mf_joining(MOQFETCH_RELATIVE_JOINING, rid, 1);
  CHECK(mf_loc_eq(mf_ok_end(), 1, 1));
  CHECK(mf_read());
  CHECK(mf_n == 3);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 0, 1, 1));
  CHECK(mf_is_obj(2, 1, 0, 1));
  CHECK(mf_fin);
  mf_obj(1, 1, 1);
  CHECK(mf_relayed(1, 1));
}

/* A relative Joining Start past group 0 starts at {0,0}. */
static void test_moqtrun_fetch_relative_join_clamped(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_joining(MOQFETCH_RELATIVE_JOINING, mf_subscribe(0), 2);
  CHECK(mf_loc_eq(mf_ok_end(), 0, 2));
  CHECK(mf_read());
  CHECK(mf_n == 2 && mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 0, 1, 1));
}

/* A subscription made before any Object has no Joining Location;
 * an absolute start past its group is out of range (10.12.2). */
static void test_moqtrun_fetch_join_invalid_range(void) {
  mf_init(sizeof mf_arena);
  u64 early = mf_subscribe(0);
  mf_obj(0, 0, 1);
  mf_joining(MOQFETCH_RELATIVE_JOINING, early, 0);
  CHECK(mf_error() == MOQCTL_ERR_INVALID_RANGE);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_joining(MOQFETCH_ABSOLUTE_JOINING, mf_subscribe(0), 1);
  CHECK(mf_error() == MOQCTL_ERR_INVALID_RANGE);
}

/* A Joining Request ID naming no subscription of this session. */
static void test_moqtrun_fetch_join_unknown_request(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  u64 rid = mf_subscribe(0);
  mf_joining(MOQFETCH_RELATIVE_JOINING, rid + 2, 0);
  CHECK(mf_error() == MOQFETCH_ERR_INVALID_JOINING_REQUEST_ID);
}

/* draft-22 FETCH (SS9.11) body without Parameters: no LOCATION_FILTER. */
static int mf_enc_fetch22_bare(wired_mspan buf, usz* off, const void* v) {
  const moqfetch_req* m = v;
  if (!moqvi_put(buf, off, m->request_id)) return 0;
  if (!moqctl_ns_put(buf, off, &m->track.ns)) return 0;
  if (!moqctl_name_put(buf, off, m->track.name)) return 0;
  return moqvi_put(buf, off, 0);
}

static int mf_enc_fetch22(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_req22_encode(buf, off, m);
}

/* B (draft-22) FETCHes alice on a fresh request stream with LOCATION_FILTER
 * rl, or with no Parameters at all when rl is 0. */
static void mf_fetch22(const moqctl_rangeloc* rl) {
  static moqfetch_req m;
  u8                  buf[MTST_MSG_MAX];
  usz                 n;
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D22;
  mf_req_sid   = mf_req_sid < MF_REQ ? MF_REQ : mf_req_sid + 4;
  m.request_id = mf_req_sid;
  m.track      = mf_track();
  m.params.n   = 0;
  if (rl) m.range = *rl;
  n = moqtrun_envelope_put(
      wired_mspan_of(buf, sizeof buf), MOQFETCH_T_FETCH,
      rl ? mf_enc_fetch22 : mf_enc_fetch22_bare, &m);
  CHECK(n != 0);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_B, mf_req_sid, wired_span_of(buf, n), 0);
}

static moqctl_rangeloc mf_rl(
    moqctl_rsk sk, u64 sg, u64 so, moqctl_rek ek, u64 eg, u64 eo) {
  moqctl_rangeloc r = {sk, sg, so, ek, eg, eo};
  return r;
}

/* draft-22 SS9.11/SS9.12: a FETCH is decoded in the draft-22 layout and
 * answered with an inclusive End Location -- the Largest Object when the
 * range reaches it (no filter: the whole track), the explicit End Object,
 * and for a range ending at a whole group the last Object returned. */
static void test_moqtrun_fetch_d22_served(void) {
  moqctl_rangeloc group0 = mf_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_GROUP, 0, 0);
  moqctl_rangeloc obj00  = mf_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_OBJ, 0, 0);
  moqctl_rangeloc cur =
      mf_rl(MOQCTL_RSK_REL_GROUP, 1, 0, MOQCTL_REK_UNBOUNDED, 0, 0);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_fetch22(0);
  CHECK(mf_loc_eq(mf_ok_end(), 1, 0));
  CHECK(mf_read() && mf_n == 3);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(2, 1, 0, 1));
  CHECK(mtst_hub.fetches[0].seq.eor_timed_out == 1);
  mf_fetch22(&group0);
  CHECK(mf_loc_eq(mf_ok_end(), 0, 1));
  CHECK(mf_read() && mf_n == 2);
  mf_fetch22(&obj00);
  CHECK(mf_loc_eq(mf_ok_end(), 0, 0));
  CHECK(mf_read() && mf_n == 1);
  mf_fetch22(&cur);
  CHECK(mf_loc_eq(mf_ok_end(), 1, 0));
  CHECK(mf_read() && mf_n == 1 && mf_is_obj(0, 1, 0, 1));
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D19;
  mf_standalone(mf_loc(0, 0), mf_loc(0, 0));
  CHECK(mf_loc_eq(mf_ok_end(), 0, 0));
}

/* A Next Object start is always past Largest (nothing to fetch) and a
 * start past Largest is INVALID_RANGE, as for draft-19. */
static void test_moqtrun_fetch_d22_invalid_range(void) {
  moqctl_rangeloc next =
      mf_rl(MOQCTL_RSK_NEXT_OBJ, 0, 0, MOQCTL_REK_UNBOUNDED, 0, 0);
  moqctl_rangeloc past =
      mf_rl(MOQCTL_RSK_ABS, 5, 0, MOQCTL_REK_UNBOUNDED, 0, 0);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_fetch22(&next);
  CHECK(mf_error() == MOQCTL_ERR_INVALID_RANGE);
  mf_fetch22(&past);
  CHECK(mf_error() == MOQCTL_ERR_INVALID_RANGE);
}

/* An absolute Joining Start n starts at {n,0} and ends at the
 * Joining Location. */
static void test_moqtrun_fetch_absolute_join(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  mf_obj(2, 0, 1);
  u64 rid = mf_subscribe(0);
  CHECK(mf_loc_eq(mtst_sub(SESS_A, SESS_B)->start, 2, 1));
  mf_joining(MOQFETCH_ABSOLUTE_JOINING, rid, 1);
  CHECK(mf_loc_eq(mf_ok_end(), 2, 1));
  CHECK(mf_read());
  CHECK(mf_n == 2 && mf_is_obj(0, 1, 0, 1) && mf_is_obj(1, 2, 0, 1));
}

/* 10.12.2: a Joining Fetch needs Forward State 1. */
static void test_moqtrun_fetch_join_forward_off(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_joining(MOQFETCH_RELATIVE_JOINING, mf_subscribe(&p0), 0);
  CHECK(mf_error() == MOQCTL_ERR_INVALID_RANGE);
}

/* ===================== publisher rejoin ===================== */

/* A rejoined publisher re-attaches B's Largest Object subscription; its
 * start and Joining Location are resolved against the new incarnation's
 * Largest (seeded by PUBLISH, 10.2.16), not kept from the old one. */
static void test_moqtrun_fetch_rejoin_reresolves_start(void) {
  moqctl_ftn    f    = mf_track();
  moqctl_params seed = {0};
  mf_init(sizeof mf_arena);
  mf_obj(5, 0, 1);
  mf_subscribe(0);
  CHECK(mf_loc_eq(mtst_sub(SESS_A, SESS_B)->start, 5, 1));
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  seed.items[0].type = MOQCTL_PARAM_LARGEST_OBJECT;
  seed.items[0].enc  = MOQCTL_PENC_LOCATION;
  seed.items[0].loc  = mf_loc(2, 3);
  seed.n             = 1;
  mtst_publish_p(SESS_C, mtst_join(SESS_C), &f, MF_ALIAS, &seed);
  wired_moqtrun_sub* s = mtst_sub(SESS_C, SESS_B);
  CHECK(s != 0);
  CHECK(s && mf_loc_eq(s->start, 2, 4));
  CHECK(s && s->has_jl && mf_loc_eq(s->jl, 2, 3));
}

/* A reliable stream that began before B's subscription start carries
 * only Objects a Joining Fetch already covers: B is not replayed onto
 * it, while an unfiltered subscriber C still is. */
static void test_moqtrun_fetch_no_replay_before_start(void) {
  moqctl_ftn f = mf_track();
  mf_init(sizeof mf_arena);
  mtst_hub.reliable_alias_limit = 100; /* alias 1: reliable */
  u64 sid                       = mf_obj_on(1, 0, 1, 0);
  mf_subscribe(0); /* start (1,1) */
  mtst_subscribe(SESS_C, mtst_join(SESS_C), &f);
  moqtrun_test_reset();
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, sid, wired_span_of(0, 0), 1);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(moqtrun_test_count_kind(5) == 1);
  CHECK(moqtrun_test_last_kind(5)->s == SESS_C);
}

void test_moqtrun_fetch(void) {
  test_moqtrun_fetch_cache_attach();
  test_moqtrun_fetch_cache_default_off();
  test_moqtrun_fetch_cache_released_on_leave();
  test_moqtrun_fetch_cache_released_on_republish();
  test_moqtrun_fetch_nothing_published();
  test_moqtrun_fetch_range_against_largest();
  test_moqtrun_fetch_end_before_start();
  test_moqtrun_fetch_unknown_track();
  test_moqtrun_fetch_serves_cached();
  test_moqtrun_fetch_no_cache_unknown();
  test_moqtrun_fetch_evicted_group_unknown();
  test_moqtrun_fetch_eviction_under_cursor();
  test_moqtrun_fetch_oversize_under_cursor();
  test_moqtrun_fetch_publisher_leaves();
  test_moqtrun_fetch_requester_leaves();
  test_moqtrun_fetch_cancelled_by_request_reset();
  test_moqtrun_fetch_data_stream_stopped();
  test_moqtrun_fetch_stall_gives_up();
  test_moqtrun_fetch_relative_join_no_gap();
  test_moqtrun_fetch_relative_join_clamped();
  test_moqtrun_fetch_join_invalid_range();
  test_moqtrun_fetch_join_unknown_request();
  test_moqtrun_fetch_d22_served();
  test_moqtrun_fetch_d22_invalid_range();
  test_moqtrun_fetch_absolute_join();
  test_moqtrun_fetch_join_forward_off();
  test_moqtrun_fetch_rejoin_reresolves_start();
  test_moqtrun_fetch_no_replay_before_start();
}
