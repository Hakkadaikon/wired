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

/* End of Range marker eor ending at {g, o} (absolute, d22 11.4.2). */
static void mupf_eor(u64 eor, u64 g, u64 o) {
  moqfetch_obj ob = {0};
  ob.flags        = eor;
  ob.group        = g;
  ob.object       = o;
  mupf_put(&ob);
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

/* The stream id of B's last fetch stream; ~0 if none. */
static u64 mupf_fetch_sid(void) {
  u64 sid = ~(u64)0;
  for (usz i = 0; i < g_n_calls; i++)
    if (mf_opens(&g_calls[i])) sid = g_calls[i].stream_id;
  return sid;
}

/* 1 iff the hub ended B's stream sid with a bare FIN. */
static int mupf_bare_fin(u64 sid) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 6 && g_calls[i].s == SESS_B &&
        g_calls[i].stream_id == sid)
      return 1;
  return 0;
}

/* B's last fetch stream decoded under B's draft (Descending when desc);
 * mf_fin also counts a bare FIN. */
static int mupf_read(int desc) {
  moqfetch_seq seq = {0};
  seq.descending   = desc;
  seq.eor_timed_out =
      (moqver_caps(mtst_ver(SESS_B)) & MOQVER_CAP_EOR_TIMED_OUT) != 0;
  int r = mf_read_seq(seq);
  mf_fin |= mupf_bare_fin(mupf_fetch_sid());
  return r;
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

/* ===================== relaying in place ===================== */

/* A, holding nothing in the cache (no arena), published {1,0} {2,0}
 * {2,1}: a FETCH of {1,0}..{2,1} lacks all of it. */
static void mupf_init_nocache(void) {
  mupf_init();
  wired_moqt_cache_attach(&mtst_hub, mupf_arena, 0);
  mf_obj(1, 0, 1);
  mf_obj(2, 0, 1);
  mf_obj(2, 1, 1);
}

static int mupf_enc_err(wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_error_encode(buf, off, m);
}

/* s answers REQUEST_ERROR e on its stream sid. */
static void mupf_up_err(
    wired_wt_session* s, i64 sid, const moqctl_request_error* e) {
  mtst_send(s, (u64)sid, MOQCTL_T_REQUEST_ERROR, mupf_enc_err, e);
}

/* A Descending FETCH (d22 3.2.1) is relayed in its own order -- Groups
 * down, Objects up within one; the upstream FETCH asks for the whole
 * range Descending too. */
static void test_moqtrun_upfetch_descending_order(void) {
  moqctl_params desc = mtst_params_u8(MOQCTL_PARAM_GROUP_ORDER, 2);
  moqfetch_req  m    = {0};
  mupf_init_nocache();
  mupf_fetch(mupf_rl(1, 0, 2, 1), &desc);
  i64                 sid = mupf_up(SESS_A, 0, &m);
  const moqctl_param* go =
      moqctl_params_find(&m.params, MOQCTL_PARAM_GROUP_ORDER);
  CHECK(sid >= 0 && go && go->u8v == 2);
  CHECK(m.range.start_group == 1 && m.range.end_group == 2);
  mupf_hdr(m.request_id, 1);
  mupf_obj(2, 0, 1);
  mupf_obj(2, 1, 1);
  mupf_obj(1, 0, 1);
  mupf_send(0);
  mupf_up_ok(sid, 2, 1);
  mupf_send(1);
  CHECK(mupf_read(1) && mf_n == 3 && mf_fin);
  CHECK(
      mf_is_obj(0, 2, 0, 1) && mf_is_obj(1, 2, 1, 1) && mf_is_obj(2, 1, 0, 1));
  CHECK(mupf_used() == 0);
}

/* An End of Range marker (absolute Location, d22 11.4.2) is the one item
 * a publisher can send out of order. Out of Descending order -- {2,0}
 * after {2,1}, or {2,1} after {1,0} -- it is never relayed: the upstream
 * FETCH is cancelled and the cache side goes on past the last one. */
static void mupf_desc_reject(int after_10) {
  moqctl_params desc = mtst_params_u8(MOQCTL_PARAM_GROUP_ORDER, 2);
  moqfetch_req  m    = {0};
  mupf_init_nocache();
  mupf_fetch(mupf_rl(1, 0, 2, 1), &desc);
  i64 sid = mupf_up(SESS_A, 0, &m);
  mupf_hdr(m.request_id, 1);
  mupf_obj(2, 0, 1);
  mupf_obj(2, 1, 1);
  if (after_10) mupf_obj(1, 0, 1);
  mupf_eor(MOQFETCH_EOR_NONEXISTENT, 2, after_10 ? 1 : 0);
  mupf_send(0);
  CHECK(mupf_read(1) && mf_fin && mf_n == (usz)(after_10 ? 4 : 3));
  CHECK(mf_is_obj(0, 2, 0, 1) && mf_is_obj(1, 2, 1, 1));
  CHECK(!after_10 || mf_is_obj(2, 1, 0, 1));
  CHECK(mf_is_unknown(after_10 ? 3 : 2, 1, MOQCACHE_OBJ_ID_MAX));
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_log_is(SESS_A, MUPF_DATA_SID, "STOP1|"));
}

static void test_moqtrun_upfetch_descending_rejects(void) {
  mupf_desc_reject(0);
  mupf_desc_reject(1);
}

/* Span groups 1..2, groups 3..4 cached, {1,0} {2,0} relayed. */
static i64 mupf_span_setup(moqfetch_req* m) {
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_cache_group(4, 1);
  mupf_fetch(mupf_rl(1, 0, 4, 0), 0);
  i64 sid = mupf_up(SESS_A, 0, m);
  mupf_hdr(m->request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_obj(2, 0, 1);
  mupf_send(0);
  return sid;
}

/* After {1,0} {2,0}: Unknown for the rest of group 2, then 3, 4, FIN. */
static int mupf_resumed_after_20(void) {
  return mupf_read(0) && mf_n == 5 && mf_fin && mf_is_obj(0, 1, 0, 1) &&
         mf_is_obj(1, 2, 0, 1) && mf_is_unknown(2, 2, MOQCACHE_OBJ_ID_MAX) &&
         mf_is_obj(3, 3, 0, 1) && mf_is_obj(4, 4, 0, 1);
}

/* d22 7.8 MUST NOT reorder: an upstream item out of place -- a repeat, one
 * behind the cursor, one past the span, one past the upstream End -- is
 * never written; the upstream FETCH is cancelled and the cache side
 * resumes just past {2,0}. */
static void mupf_out_of_place(int how) {
  moqfetch_req m   = {0};
  i64          sid = mupf_span_setup(&m);
  if (how == 3) mupf_up_ok(sid, 2, 1);
  if (how == 1) /* only a marker can name a Location behind the last */
    mupf_eor(MOQFETCH_EOR_UNKNOWN, 1, 5);
  else
    mupf_obj(how == 2 ? 3 : 2, how == 3 ? 5 : 0, 1);
  mupf_send(0);
  CHECK(mupf_resumed_after_20());
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_used() == 0);
}

static void test_moqtrun_upfetch_out_of_place(void) {
  for (int how = 0; how < 4; how++) {
    int fails = wired_test_fails;
    mupf_out_of_place(how);
    if (wired_test_fails != fails) printf("  ^ out of place %d\n", how);
  }
}

/* d22 7.8: a relayed item the transport refuses cancels the upstream
 * FETCH in the same call; the cache side serves from the cursor. */
static void test_moqtrun_upfetch_refused_write(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  g_stream_send_reject_n = 1;
  mupf_send(0);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_read(0) && mf_n == 2 && mf_fin);
  CHECK(mf_is_unknown(0, 2, MOQCACHE_OBJ_ID_MAX) && mf_is_obj(1, 3, 0, 1));
}

/* While the upstream FETCH runs the tick neither serves the cache side
 * nor stall-checks it (even with the stall clock long past); a relayed
 * item restarts that clock. */
static void test_moqtrun_upfetch_tick_leaves_leg(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  wired_moqt_tick(&mtst_hub, 20000);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  i64 sid                        = mupf_up(SESS_A, 0, &m);
  mtst_hub.fetches[0].last_ok_ms = 0; /* stale stall clock */
  wired_moqt_tick(&mtst_hub, 20001);
  CHECK(!mf_read() && mtst_hub.fetches[0].in_use);
  CHECK(mupf_log_is(SESS_A, (u64)sid, ""));
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_send(0);
  CHECK(mtst_hub.fetches[0].last_ok_ms == 20001);
  CHECK(mupf_read(0) && mf_n == 1);
}

/* d22 9.12: an End before the Start closes A PROTOCOL_VIOLATION; an End
 * below an item already relayed cancels the upstream FETCH. Either way
 * the cache side takes over. */
static void test_moqtrun_upfetch_bad_end(void) {
  moqfetch_req m   = {0};
  i64          sid = mupf_span_setup(&m);
  mupf_up_ok(sid, 0, 0);
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  CHECK(
      c && c->s == SESS_A &&
      c->stream_id == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
  CHECK(mupf_resumed_after_20());
  sid = mupf_span_setup(&m);
  mupf_up_ok(sid, 1, 4);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_resumed_after_20());
}

/* d22 3.2.4 / 9.4: a FETCH still unanswered gets the upstream
 * REQUEST_ERROR as is -- code, Retry Interval, a REDIRECT's Redirect --
 * and the data stream it already got is reset; the hub FINs its request
 * stream and stops the upstream data stream. */
static void test_moqtrun_upfetch_error_passthrough(void) {
  static moqctl_request_error e;
  moqctl_request_error        got = {0};
  moqfetch_ok                 ok  = {0};
  moqfetch_req                m   = {0};
  mupf_init();
  mupf_vers(MOQVER_D22);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  i64 sid = mupf_up(SESS_C, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_obj(0, 0, 1);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 0);
  e                          = (moqctl_request_error){0};
  e.error_code               = MOQCTL_ERR_REDIRECT;
  e.retry_interval           = 7;
  e.has_redirect             = 1;
  e.redirect.connect_uri     = mtst_z("https://r.example/moq");
  e.redirect.track_namespace = mtns_ns("x/y");
  e.redirect.track_name      = mtst_z("z");
  mupf_up_err(SESS_C, sid, &e);
  CHECK(mupf_reply(&ok, &got) == MOQCTL_T_REQUEST_ERROR);
  CHECK(got.error_code == MOQCTL_ERR_REDIRECT && got.retry_interval == 7);
  CHECK(got.has_redirect && got.redirect.connect_uri.n == 21);
  CHECK(got.redirect.track_namespace.n == 2 && got.redirect.track_name.n == 1);
  const moqtrun_test_call* r = moqtrun_test_last_kind(7);
  CHECK(r && r->s == SESS_B);
  CHECK(mupf_log_is(SESS_C, (u64)sid, "FIN|"));
  CHECK(mupf_log_is(SESS_C, MUPF_DATA_SID, "STOP1|"));
  CHECK(mupf_used() == 0);
}

/* A held track's FETCH was answered already: an upstream REQUEST_ERROR
 * only hands over to the cache side, Unknown where it lacks Objects. */
static void test_moqtrun_upfetch_error_held(void) {
  moqctl_request_error e   = {0};
  moqfetch_req         m   = {0};
  i64                  sid = mupf_span_setup(&m);
  e.error_code             = MOQCTL_ERR_INVALID_RANGE;
  mupf_up_err(SESS_A, sid, &e);
  CHECK(mupf_n_msgs(MOQCTL_T_REQUEST_ERROR) == 0);
  CHECK(mupf_resumed_after_20());
  CHECK(mupf_log_is(SESS_A, (u64)sid, "FIN|"));
}

/* The upstream resets its data stream, sends GOAWAY on the request
 * stream (not re-issued), or its session closes: the leg ends, the cache
 * side takes over at the cursor (d22 3.2.3, 9.2). */
static void mupf_leg_ends(int how) {
  static const u8 goaway[] = {0x10, 0x00, 0x01, 0x00}; /* GOAWAY, no URI */
  moqfetch_req    m        = {0};
  i64             sid      = mupf_span_setup(&m);
  if (how == 0)
    wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MUPF_DATA_SID, 1, 0);
  if (how == 1)
    wired_moqt_on_stream_data(
        &mtst_hub, SESS_A, (u64)sid, wired_span_of(goaway, 4), 0);
  if (how == 2) wired_moqt_on_session_close(&mtst_hub, SESS_A);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mupf_read(0) && mf_fin && mf_is_obj(1, 2, 0, 1));
  CHECK(how == 2 || mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(how != 0 || mupf_log_is(SESS_A, MUPF_DATA_SID, ""));
  CHECK(mupf_used() == 0);
}

static void test_moqtrun_upfetch_leg_ends(void) {
  for (int how = 0; how < 3; how++) {
    int fails = wired_test_fails;
    mupf_leg_ends(how);
    if (wired_test_fails != fails) printf("  ^ leg end %d\n", how);
  }
}

/* d22 9.2: a second GOAWAY on the one request stream closes the session
 * PROTOCOL_VIOLATION. */
static void test_moqtrun_upfetch_two_goaways(void) {
  static const u8 two[] = {0x10, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00};
  moqfetch_req    m     = {0};
  i64             sid   = mupf_span_setup(&m);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, (u64)sid, wired_span_of(two, sizeof two), 0);
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  CHECK(
      c && c->s == SESS_A &&
      c->stream_id == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* d22 3.2.2: FIN then FETCH_OK completes the leg as FETCH_OK then FIN
 * does -- the hub FINs its request stream, the cache suffix once. */
static void test_moqtrun_upfetch_fin_then_ok(void) {
  moqfetch_req m   = {0};
  i64          sid = mupf_span_setup(&m);
  mupf_send(1);
  CHECK(mupf_log_is(SESS_A, (u64)sid, ""));
  mupf_up_ok(sid, 2, MOQFETCH_OBJ_GROUP_END);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "FIN|"));
  CHECK(mupf_read(0) && mf_n == 4 && mf_fin);
  CHECK(mf_is_obj(2, 3, 0, 1) && mf_is_obj(3, 4, 0, 1));
}

/* d22 3.2.1: a FETCH whose upstream answer is empty and leaves nothing
 * for the cache gets the header alone, then FIN. */
static void test_moqtrun_upfetch_empty_answer(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  i64 sid = mupf_up(SESS_C, 0, &m);
  mupf_up_ok_p(SESS_C, sid, mf_loc(5, 0), 0, wired_span_of(0, 0));
  mupf_hdr(m.request_id, 0);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 1);
  CHECK(mupf_n_msgs(MOQFETCH_T_FETCH_OK) == 1);
  CHECK(mupf_read(0) && mf_n == 0 && mf_fin);
  CHECK(mupf_used() == 0);
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
  test_moqtrun_upfetch_descending_order();
  test_moqtrun_upfetch_descending_rejects();
  test_moqtrun_upfetch_out_of_place();
  test_moqtrun_upfetch_refused_write();
  test_moqtrun_upfetch_tick_leaves_leg();
  test_moqtrun_upfetch_bad_end();
  test_moqtrun_upfetch_error_passthrough();
  test_moqtrun_upfetch_error_held();
  test_moqtrun_upfetch_leg_ends();
  test_moqtrun_upfetch_two_goaways();
  test_moqtrun_upfetch_fin_then_ok();
  test_moqtrun_upfetch_empty_answer();
}
