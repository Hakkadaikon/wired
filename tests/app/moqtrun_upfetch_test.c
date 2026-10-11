/* Upstream FETCH: a FETCH (or fill) whose range the hub cache cannot
 * vouch for is completed by one FETCH the hub sends to a matching
 * publisher (draft-ietf-moq-transport-22 3.2.3, 7.6, 9.11/9.12, 11.4,
 * 12.1). Shares the recording io stubs (moqtrun_test.c) and the fixtures
 * of moqtrun_sub_test.c, moqtrun_fetch_test.c, moqtrun_fill_test.c,
 * moqtrun_ns_test.c, moqtrun_rdv_test.c and moqtrun_upsub_test.c (same
 * unity TU). */

/* ===================== fixtures ===================== */

/* A publishes alice (its owner), C announces chat/room1 on its request
 * stream MUPF_NS_SID, B fetches. Upstream data streams are client uni
 * streams (2 mod 4, RFC 9000 2.1). */
#define MUPF_NS_SID 4
#define MUPF_DATA_SID 1002

static u8 mupf_arena[64 * (MOQCACHE_HDR + 16)];

/* B runs draft bv; A and C the default draft, so A's PUBLISH and the
 * SUBGROUP streams that fill the cache read as every other fetch test's
 * (mupf_vers moves them later). */
static void mupf_init_v(int bv) {
  moqctl_ftn f = mf_track();
  mtst_init();
  wired_moqt_cache_attach(&mtst_hub, mupf_arena, sizeof mupf_arena);
  mf_pub_sid = 2;
  mf_ctrl_a  = mtst_join(SESS_A);
  mf_ctrl_b  = mtst_join(SESS_B);
  mtst_join(SESS_C);
  mtst_publish(SESS_A, mf_ctrl_a, &f, MF_ALIAS);
  mtns_pub(SESS_C, MUPF_NS_SID, "chat/room1");
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = bv;
  g_next_stream_id = 201; /* server-initiated bidi: 1 mod 4 */
}

static void mupf_init(void) { mupf_init_v(MOQVER_D22); }

/* A and C now run draft uv. */
static void mupf_vers(int uv) {
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = uv;
  moqtrun_find_by_wt(&mtst_hub, SESS_C)->ver = uv;
}

/* A sends Objects {g, 0} .. {g, n-1} (one byte each) into the cache. */
static void mupf_cache_group(u64 g, u64 n) {
  for (u64 o = 0; o < n; o++) mf_obj(g, o, 1);
}

static int mupf_enc22(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_req22_encode(buf, off, m);
}

static int mupf_enc19(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_req19_encode(buf, off, m);
}

static moqtrun_body_encode_fn mupf_enc_for(wired_wt_session* s) {
  return (moqver_caps(mtst_ver(s)) & MOQVER_CAP_FETCH_BODY_V22) ? mupf_enc22
                                                                : mupf_enc19;
}

/* The range {sg, so} .. {eg, eo} (inclusive). */
static moqctl_rangeloc mupf_rl(u64 sg, u64 so, u64 eg, u64 eo) {
  moqctl_rangeloc r = {MOQCTL_RSK_ABS, sg, so, MOQCTL_REK_OBJ, eg, eo};
  return r;
}

/* s FETCHes track f over rl with params (0: none) on a fresh request
 * stream, in s's own draft; mf_req_sid is that stream. */
static void mupf_fetch_on(
    wired_wt_session*    s,
    moqctl_ftn           f,
    moqctl_rangeloc      rl,
    const moqctl_params* params) {
  static moqfetch_req m;
  u8                  buf[MTST_MSG_MAX];
  mf_req_sid   = mf_req_sid < MF_REQ ? MF_REQ : mf_req_sid + 4;
  m            = (moqfetch_req){0};
  m.request_id = mf_req_sid;
  m.fetch_type = MOQFETCH_STANDALONE;
  m.track      = f;
  m.range      = rl;
  if (params) m.params = *params;
  usz n = moqtrun_envelope_put(
      wired_mspan_of(buf, sizeof buf), MOQFETCH_T_FETCH, mupf_enc_for(s), &m);
  CHECK(n != 0);
  wired_moqt_on_stream_data(&mtst_hub, s, mf_req_sid, wired_span_of(buf, n), 0);
}

static void mupf_fetch(moqctl_rangeloc rl, const moqctl_params* params) {
  mupf_fetch_on(SESS_B, mf_track(), rl, params);
}

/* The which-th FETCH the hub opened toward s, decoded in s's draft into
 * *m; its stream id, -1 if there is none. */
static i64 mupf_up(wired_wt_session* s, usz which, moqfetch_req* m) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0;
    u64                      type;
    wired_span               body;
    if (c->kind != 1 || c->s != s) continue;
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type != MOQFETCH_T_FETCH || n++ != which) continue;
    if (moqver_caps(mtst_ver(s)) & MOQVER_CAP_FETCH_BODY_V22)
      CHECK(moqfetch_req22_take(body, m) == MOQCTL_OK);
    else
      CHECK(moqfetch_req19_take(mtst_ver(s), body, m) == MOQCTL_OK);
    return (i64)c->stream_id;
  }
  return -1;
}

/* FETCHes the hub sent toward s. */
static usz mupf_n_up(wired_wt_session* s) {
  moqfetch_req m;
  usz          n = 0;
  while (mupf_up(s, n, &m) >= 0) n++;
  return n;
}

static int mupf_enc_ok22(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_ok_encode(buf, off, m);
}

static int mupf_enc_ok19(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_ok19_encode(buf, off, m);
}

/* s answers FETCH_OK (End Location end, inclusive) on its stream sid. */
static void mupf_up_ok_p(
    wired_wt_session* s, i64 sid, moqctl_loc end, u64 eot, wired_span props) {
  static moqfetch_ok ok;
  ok                  = (moqfetch_ok){0};
  ok.end              = end;
  ok.end_of_track     = eot;
  ok.track_properties = props;
  mtst_send(
      s, (u64)sid, MOQFETCH_T_FETCH_OK,
      (moqver_caps(mtst_ver(s)) & MOQVER_CAP_FETCH_END_INCLUSIVE)
          ? mupf_enc_ok22
          : mupf_enc_ok19,
      &ok);
}

static void mupf_up_ok(i64 sid, u64 g, u64 o) {
  mupf_up_ok_p(SESS_A, sid, mf_loc(g, o), 0, wired_span_of(0, 0));
}

/* An upstream fetch data stream being built. */
static u8           mupf_buf[1024];
static usz          mupf_n;
static moqfetch_seq mupf_seq;

/* FETCH_HEADER for Request ID rid; desc for a Descending FETCH. */
static void mupf_hdr(u64 rid, int desc) {
  mupf_n                 = 0;
  mupf_seq               = (moqfetch_seq){0};
  mupf_seq.descending    = desc;
  mupf_seq.eor_timed_out = 1;
  CHECK(moqfetch_hdr_put(
      wired_mspan_of(mupf_buf, sizeof mupf_buf), &mupf_n, rid));
}

static void mupf_put(const moqfetch_obj* o) {
  CHECK(moqfetch_obj_put(
      wired_mspan_of(mupf_buf, sizeof mupf_buf), &mupf_n, &mupf_seq, o));
}

/* Object {g, o} of n bytes, each first, Subgroup 0, priority 128. */
static void mupf_obj_b(u64 g, u64 o, usz n, u8 first) {
  static u8    pl[64];
  moqfetch_obj ob = {0};
  for (usz i = 0; i < n; i++) pl[i] = first;
  ob.flags = MOQFETCH_F_OBJECT | MOQFETCH_F_PRIORITY |
             (!mupf_seq.have_loc || mupf_seq.group != g ? MOQFETCH_F_GROUP : 0);
  ob.group = g;
  ob.object       = o;
  ob.has_subgroup = 1;
  ob.priority     = 128;
  ob.payload      = wired_span_of(pl, n);
  mupf_put(&ob);
}

/* Object {g, o} of n bytes (each 16*g+o, as mf_is_obj reads them). */
static void mupf_obj(u64 g, u64 o, usz n) {
  mupf_obj_b(g, o, n, (u8)(16 * g + o));
}

/* s delivers the built bytes on its data stream sid. */
static void mupf_send_on(wired_wt_session* s, u64 sid, int fin) {
  wired_moqt_on_stream_data(
      &mtst_hub, s, sid, wired_span_of(mupf_buf, mupf_n), fin);
  mupf_n = 0;
}

static void mupf_send(int fin) { mupf_send_on(SESS_A, MUPF_DATA_SID, fin); }

/* Fetch slots in use. */
static usz mupf_used(void) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    n += mtst_hub.fetches[i].in_use != 0;
  return n;
}

/* B's last fetch stream decoded under B's draft (Descending when desc). */
static int mupf_read(int desc) {
  moqfetch_seq seq = {0};
  seq.descending   = desc;
  seq.eor_timed_out =
      (moqver_caps(mtst_ver(SESS_B)) & MOQVER_CAP_EOR_TIMED_OUT) != 0;
  return mf_read_seq(seq);
}

/* The first reply on B's last request stream: its Type (0 when none),
 * decoded in B's draft into *ok or *e. */
static u64 mupf_reply(moqfetch_ok* ok, moqctl_request_error* e) {
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0, boff = 0;
    u64                      type = 0;
    wired_span               body;
    if (c->s != SESS_B || c->stream_id != mf_req_sid) continue;
    if (c->kind != 12 && c->kind != 3) continue;
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type == MOQFETCH_T_FETCH_OK)
      CHECK(moqfetch_ok_take(mtst_ver(SESS_B), body, ok) == MOQCTL_OK);
    if (type == MOQCTL_T_REQUEST_ERROR)
      CHECK(moqctl_request_error_take(body, &boff, e) == MOQCTL_OK);
    return type;
  }
  return 0;
}

/* Hub ops on s's stream sid: "RST<code>|", "STOP<code>|", "FIN|". */
static const char* mupf_log(wired_wt_session* s, u64 sid) {
  mrdv_at = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    if (c->s != s || c->stream_id != sid) continue;
    if (c->kind == 6) mrdv_put("FIN|");
    if (c->kind == 7) mrdv_put("RST");
    if (c->kind == 13) mrdv_put("STOP");
    if (c->kind == 7 || c->kind == 13) {
      mrdv_put_hex((u64)c->fin);
      mrdv_put("|");
    }
  }
  mrdv_text[mrdv_at] = 0;
  return mrdv_text;
}

static int mupf_log_is(wired_wt_session* s, u64 sid, const char* want) {
  const char* got = mupf_log(s, sid);
  usz         i   = 0;
  while (got[i] && got[i] == want[i]) i++;
  if (got[i] != want[i]) printf("  log got \"%s\" want \"%s\"\n", got, want);
  return got[i] == want[i];
}

/* ===================== GOAWAY'd peers are not asked ===================== */

/* draft-22 9.2: after a GOAWAY on the control stream, either way, no new
 * request goes to that peer -- not even the hub's upstream SUBSCRIBE. */
static void mupf_upsub_goaway(int recv) {
  mups_init();
  wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  a->sess.goaway_recv   = recv;
  a->sess.goaway_sent   = !recv;
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mups_n_up(SESS_A) == 0);
}

static void test_moqtrun_upfetch_upsub_skips_goaway(void) {
  mupf_upsub_goaway(1);
  mupf_upsub_goaway(0);
}

/* ===================== held track ===================== */

/* d22 3.2.3: groups 1..2 are older than the oldest cached group, so they
 * go upstream to the track's own publisher in one FETCH {1,0}..{2, whole
 * group} in the same group order; FETCH_OK goes to B at once with the
 * hub's own End. The relayed Objects come first, then the cached ones,
 * each once; the hub FINs its request stream to A and the slot frees. */
static void test_moqtrun_upfetch_gap_to_owner(void) {
  moqfetch_req         m  = {0};
  moqfetch_ok          ok = {0};
  moqctl_request_error e;
  mupf_init();
  mupf_cache_group(3, 2);
  mupf_cache_group(4, 2);
  mupf_fetch(mupf_rl(1, 0, 4, 1), 0);
  CHECK(mupf_reply(&ok, &e) == MOQFETCH_T_FETCH_OK);
  CHECK(mf_loc_eq(ok.end, 4, 1) && ok.end_of_track == 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  CHECK(sid >= 0 && mupf_n_up(SESS_C) == 0);
  CHECK((m.request_id & 1) == 1);
  CHECK(m.range.sk == MOQCTL_RSK_ABS && m.range.start_group == 1);
  CHECK(m.range.start_object == 0);
  CHECK(m.range.ek == MOQCTL_REK_GROUP && m.range.end_group == 2);
  CHECK(moqctl_params_find(&m.params, MOQCTL_PARAM_GROUP_ORDER) == 0);
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_obj(2, 0, 1);
  mupf_send(0);
  mupf_up_ok(sid, 2, MOQFETCH_OBJ_GROUP_END); /* the whole range asked */
  mupf_send(1);
  CHECK(mupf_read(0) && mf_n == 6 && mf_fin);
  CHECK(mf_is_obj(0, 1, 0, 1) && mf_is_obj(1, 2, 0, 1));
  CHECK(mf_is_obj(2, 3, 0, 1) && mf_is_obj(3, 3, 1, 1));
  CHECK(mf_is_obj(4, 4, 0, 1) && mf_is_obj(5, 4, 1, 1));
  CHECK(mf_hdr_rid == mf_req_sid);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "FIN|"));
  CHECK(mupf_used() == 0);
}

/* A fill with a cache gap (d22 3.4): the same one FETCH upstream, the
 * fill stream carrying the SUBSCRIBE's Request ID, relayed then cached,
 * FIN -- and no FETCH_OK anywhere toward B. */
static void test_moqtrun_upfetch_fill_gap(void) {
  moqfetch_fill fill = {0};
  moqfetch_req  m    = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  fill.has_filter        = 1;
  fill.range.sk          = MOQCTL_RSK_ABS;
  fill.range.start_group = 1;
  fill.range.ek          = MOQCTL_REK_UNBOUNDED;
  u64 rid                = mfill_subscribe(&fill, 0);
  i64 sid                = mupf_up(SESS_A, 0, &m);
  CHECK(sid >= 0);
  CHECK(m.range.start_group == 1 && m.range.end_group == 2);
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_obj(2, 0, 1);
  mupf_send(0);
  mupf_up_ok(sid, 2, MOQFETCH_OBJ_GROUP_END); /* the whole range asked */
  mupf_send(1);
  CHECK(mupf_read(0) && mf_n == 3 && mf_fin);
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_is_obj(0, 1, 0, 1) && mf_is_obj(1, 2, 0, 1));
  CHECK(mf_is_obj(2, 3, 0, 1));
  for (usz i = 0; i < g_n_calls; i++)
    CHECK(
        !(g_calls[i].s == SESS_B && g_calls[i].payload_len &&
          g_calls[i].payload[0] == MOQFETCH_T_FETCH_OK));
  CHECK(mupf_used() == 0);
}

/* Fully cached: no upstream request at all. */
static void test_moqtrun_upfetch_cached_no_upstream(void) {
  mupf_init();
  mupf_cache_group(0, 1);
  mupf_cache_group(1, 1);
  mupf_fetch(mupf_rl(0, 0, 1, 0), 0);
  CHECK(mupf_n_up(SESS_A) == 0 && mupf_n_up(SESS_C) == 0);
  CHECK(mupf_read(0) && mf_n == 2 && mf_fin);
}

/* d22 7.8 / 11.4: a relayed Object keeps its Subgroup ID, Publisher
 * Priority, Properties, Datagram flag and payload; the first downstream
 * Object names absolute IDs, the header B's own Request ID. */
static void test_moqtrun_upfetch_reencode(void) {
  static const u8 props[] = {0x0C, 0x01}; /* one even-type KVP */
  moqfetch_obj    a = {0}, d = {0}, o = {0};
  moqfetch_req    m   = {0};
  moqfetch_seq    seq = {0};
  u8              buf[512];
  u64             rid = 0;
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  CHECK(mupf_up(SESS_A, 0, &m) >= 0);
  mupf_hdr(m.request_id, 0);
  a.flags        = MOQFETCH_F_OBJECT | MOQFETCH_F_GROUP | MOQFETCH_F_PRIORITY |
                   MOQFETCH_F_PROPS | MOQFETCH_F_SUBGROUP_MASK;
  a.group        = 1;
  a.object       = 5;
  a.has_subgroup = 1;
  a.subgroup     = 7;
  a.priority     = 9;
  a.has_props    = 1;
  a.props        = wired_span_of(props, sizeof props);
  a.payload      = wired_span_of((const u8*)"xy", 2);
  mupf_put(&a);
  d.flags    = MOQFETCH_F_OBJECT | MOQFETCH_F_DATAGRAM | MOQFETCH_F_GROUP;
  d.group    = 2;
  d.object   = 1;
  d.priority = 9;
  d.payload  = wired_span_of((const u8*)"z", 1);
  mupf_put(&d);
  mupf_send(0);
  usz        len = mf_gather(buf), off = 0;
  wired_span all    = wired_span_of(buf, len);
  seq.eor_timed_out = 1;
  CHECK(moqfetch_hdr_take(all, &off, &rid) == MOQCTL_OK);
  CHECK(rid == mf_req_sid);
  CHECK(moqfetch_obj_take(all, &off, &seq, &o) == MOQCTL_OK);
  CHECK(o.group == 1 && o.object == 5 && o.subgroup == 7 && o.priority == 9);
  CHECK(o.has_props && o.props.n == 2 && o.payload.n == 2);
  CHECK(o.payload.n && o.payload.p[0] == 'x');
  CHECK(!(o.flags & MOQFETCH_F_DATAGRAM));
  CHECK(moqfetch_obj_take(all, &off, &seq, &o) == MOQCTL_OK);
  CHECK(o.group == 2 && o.object == 1 && (o.flags & MOQFETCH_F_DATAGRAM));
  CHECK(!o.has_subgroup && o.priority == 9 && o.payload.n == 1);
}

/* d22 7.4 aggregation is a MAY: two FETCHes of one missing range get two
 * upstream FETCHes, each with its own odd Request ID. */
static void test_moqtrun_upfetch_two_not_shared(void) {
  moqfetch_req m0 = {0}, m1 = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  CHECK(mupf_up(SESS_A, 0, &m0) >= 0 && mupf_up(SESS_A, 1, &m1) >= 0);
  CHECK((m0.request_id & 1) && (m1.request_id & 1));
  CHECK(m0.request_id != m1.request_id);
}

/* The upstream FETCH is spelled in the upstream session's own draft. */
static void test_moqtrun_upfetch_upstream_draft(void) {
  for (int v = 0; v < MOQVER_COUNT; v++) {
    moqfetch_req m = {0};
    mupf_init();
    mupf_cache_group(3, 1);
    mupf_vers(v);
    mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
    CHECK(mupf_up(SESS_A, 0, &m) >= 0);
    CHECK(m.range.start_group == 1 && m.range.end_group == 2);
  }
}

/* ===================== who is asked ===================== */

static moqctl_ftn mupf_bob(void) { return mtst_ftn("chat", "room1", "bob"); }

/* Rounds on B's last request stream opening with a message of type. */
static usz mupf_n_msgs(u64 type) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0;
    u64                      t   = 0;
    wired_span               body;
    if (c->s != SESS_B || c->stream_id != mf_req_sid) continue;
    if (c->kind != 12 && c->kind != 3) continue;
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &t, &body);
    n += t == type;
  }
  return n;
}

/* The request error code B got, as B's draft spells code. */
static int mupf_refused(u64 code) {
  moqfetch_ok          ok = {0};
  moqctl_request_error e  = {0};
  return mupf_reply(&ok, &e) == MOQCTL_T_REQUEST_ERROR &&
         e.error_code == moqctl_request_error_for(mtst_ver(SESS_B), code);
}

/* A wait for a new path for bob that already tried s. */
static void mupf_tried(wired_wt_session* s) {
  moqctl_ftn         f = mupf_bob();
  wired_moqtrun_rdv* r = &mtst_hub.rdv[0];
  usz                n = 0;
  CHECK(moqctl_ns_put(wired_mspan_of(r->ns, sizeof r->ns), &n, &f.ns));
  r->ns_len   = n;
  r->name_len = f.name.n;
  for (usz i = 0; i < f.name.n; i++) r->name[i] = f.name.p[i];
  r->in_use = 1;
  r->repath = 1;
  r->wt     = SESS_D;
  r->tried  = moqtrun_rp_bit(&mtst_hub, s);
}

/* d22 7.6 / 9.2: an owner that may not be asked -- GOAWAY either way,
 * being closed by the hub, or the requester itself -- leaves the FETCH to
 * a covering announcer (C), never to the excluded one. */
static void mupf_owner_excluded(int how) {
  wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  wired_wt_session*   s = how == 3 ? SESS_A : SESS_B;
  mupf_init();
  mupf_cache_group(3, 1);
  a->sess.goaway_recv = how == 0;
  a->sess.goaway_sent = how == 1;
  a->closing          = how == 2;
  mupf_fetch_on(s, mf_track(), mupf_rl(1, 0, 3, 0), 0);
  CHECK(mupf_n_up(SESS_A) == 0 && mupf_n_up(SESS_C) == 1);
}

static void test_moqtrun_upfetch_owner_excluded(void) {
  for (int how = 0; how < 4; how++) {
    int fails = wired_test_fails;
    mupf_owner_excluded(how);
    if (wired_test_fails != fails) printf("  ^ exclusion %d\n", how);
  }
}

/* A track nobody holds goes to an announcer not yet tried by a wait for
 * a new path; with only a tried one, DOES_NOT_EXIST. */
static void test_moqtrun_upfetch_tried_announcer_skipped(void) {
  mupf_init();
  mtst_join(SESS_D);
  mupf_tried(SESS_C);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 1, 0), 0);
  CHECK(mupf_n_up(SESS_C) == 0);
  CHECK(mupf_refused(MOQCTL_ERR_DOES_NOT_EXIST));
}

/* No publisher to ask (both GOAWAY'd), or no request stream toward it:
 * the cache alone answers, Unknown where it lacks Objects, then FIN. */
static void mupf_cache_only(int refuse) {
  mupf_init();
  mupf_cache_group(2, 1);
  mupf_cache_group(3, 1);
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->sess.goaway_recv = !refuse;
  moqtrun_find_by_wt(&mtst_hub, SESS_C)->sess.goaway_recv = !refuse;
  g_open_bidi_fail_n                                      = refuse;
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  CHECK(mupf_n_msgs(MOQFETCH_T_FETCH_OK) == 1);
  CHECK(mupf_read(0) && mf_n == 3 && mf_fin);
  CHECK(mf_is_unknown(0, 1, MOQCACHE_OBJ_ID_MAX));
  CHECK(mf_is_obj(1, 2, 0, 1) && mf_is_obj(2, 3, 0, 1));
  CHECK(mupf_used() == 0);
}

static void test_moqtrun_upfetch_cache_only(void) {
  mupf_cache_only(0);
  mupf_cache_only(1);
}

/* ===================== a track the hub does not hold ===================== */

/* d22 7.6: the whole range goes to the covering announcer; B hears no
 * FETCH_OK until C's, which it then copies -- End Location, End Of Track
 * and Track Properties (7.7) -- exactly once; C's Objects before it are
 * relayed already. */
static void test_moqtrun_upfetch_no_track_waits_ok(void) {
  static const u8      props[] = {0x0C, 0x05}; /* one even-type KVP */
  moqfetch_req         m       = {0};
  moqfetch_ok          ok      = {0};
  moqctl_request_error e;
  mupf_init();
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  i64 sid = mupf_up(SESS_C, 0, &m);
  CHECK(sid >= 0 && mupf_n_up(SESS_A) == 0);
  CHECK(m.range.start_group == 0 && m.range.start_object == 0);
  CHECK(m.range.ek == MOQCTL_REK_OBJ && m.range.end_group == 5);
  CHECK(mupf_reply(&ok, &e) == 0);
  mupf_hdr(m.request_id, 0);
  mupf_obj(0, 0, 1);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 0);
  CHECK(mupf_read(0) && mf_n == 1 && mf_is_obj(0, 0, 0, 1));
  mupf_up_ok_p(SESS_C, sid, mf_loc(2, 3), 1, wired_span_of(props, 2));
  CHECK(mupf_reply(&ok, &e) == MOQFETCH_T_FETCH_OK);
  CHECK(mf_loc_eq(ok.end, 2, 3) && ok.end_of_track == 1);
  CHECK(ok.track_properties.n == 2 && ok.track_properties.p[1] == 0x05);
  CHECK(mupf_n_msgs(MOQFETCH_T_FETCH_OK) == 1);
}

/* d22 9.20.5 / 7.6: no covering announcer is DOES_NOT_EXIST, FILL_TIMEOUT
 * 0 is TIMEOUT, no request stream toward the announcer EXCESSIVE_LOAD --
 * each leaving no slot behind. */
static void test_moqtrun_upfetch_no_track_refusals(void) {
  moqctl_params ft0 = mtst_params_vi(MOQCTL_PARAM_FILL_TIMEOUT, 0);
  mupf_init();
  mupf_fetch_on(
      SESS_B, mtst_ftn("other", "room1", "bob"), mupf_rl(0, 0, 1, 0), 0);
  CHECK(mupf_refused(MOQCTL_ERR_DOES_NOT_EXIST) && mupf_used() == 0);
  mupf_init();
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 1, 0), &ft0);
  CHECK(mupf_refused(MOQTRUN_ERR_TIMEOUT) && mupf_used() == 0);
  CHECK(mupf_n_up(SESS_C) == 0);
  mupf_init();
  g_open_bidi_fail_n = 1;
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 1, 0), 0);
  CHECK(mupf_refused(MOQCTL_ERR_EXCESSIVE_LOAD) && mupf_used() == 0);
}

/* The hub's own tracks (blob, live) are never fetched upstream, even
 * where an announcer covers their name. */
static void test_moqtrun_upfetch_hub_owned(void) {
  static const u8 frag[1] = {1};
  wired_span      fr      = wired_span_of(frag, 1);
  mupf_init();
  CHECK(
      wired_moqt_publish_live(&mtst_hub, mtst_z("bob"), 9, &fr, 1, 1000, 0) ==
      1);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 1, 0), 0);
  CHECK(mupf_n_up(SESS_C) == 0 && mupf_refused(MOQCTL_ERR_DOES_NOT_EXIST));
  mupf_init();
  mtst_hub.blob_track.in_use   = 1;
  mtst_hub.blob_track.name_len = 3;
  for (usz i = 0; i < 3; i++) mtst_hub.blob_track.name[i] = (u8) "bob"[i];
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 1, 0), 0);
  CHECK(mupf_n_up(SESS_C) == 0 && mupf_refused(MOQCTL_ERR_DOES_NOT_EXIST));
}

/* draft-22 7.4: a reserved (.session) namespace is DOES_NOT_EXIST and an
 * unauthorized FETCH UNAUTHORIZED, both before any routing -- nothing goes
 * upstream even where an announcer of every namespace exists. */
static int mupf_deny(void* ctx, const moqctl_ftn* name, const moqctl_token* t) {
  (void)ctx;
  (void)name;
  (void)t;
  return 0;
}

static void test_moqtrun_upfetch_refused_before_routing(void) {
  mupf_init();
  mtns_pub(SESS_C, MUPF_NS_SID + 4, ""); /* covers every namespace */
  mupf_fetch_on(SESS_B, mtst_ftn(".session", "x", "y"), mupf_rl(0, 0, 1, 0), 0);
  CHECK(mupf_n_up(SESS_C) == 0 && mupf_refused(MOQCTL_ERR_DOES_NOT_EXIST));
  mupf_init();
  mupf_cache_group(3, 1);
  mtst_hub.authorize_subscribe = mupf_deny;
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  CHECK(mupf_n_up(SESS_A) == 0 && mupf_refused(MOQCTL_ERR_UNAUTHORIZED));
}

void test_moqtrun_upfetch(void) {
  test_moqtrun_upfetch_upsub_skips_goaway();
  test_moqtrun_upfetch_gap_to_owner();
  test_moqtrun_upfetch_fill_gap();
  test_moqtrun_upfetch_cached_no_upstream();
  test_moqtrun_upfetch_reencode();
  test_moqtrun_upfetch_two_not_shared();
  test_moqtrun_upfetch_upstream_draft();
  test_moqtrun_upfetch_owner_excluded();
  test_moqtrun_upfetch_tried_announcer_skipped();
  test_moqtrun_upfetch_cache_only();
  test_moqtrun_upfetch_no_track_waits_ok();
  test_moqtrun_upfetch_no_track_refusals();
  test_moqtrun_upfetch_hub_owned();
  test_moqtrun_upfetch_refused_before_routing();
}
