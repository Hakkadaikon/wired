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
  for (u64 o = 0; o < n; o++) {
    mf_obj(g, o, 1);
  }
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
  if (params) {
    m.params = *params;
  }
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
    if (c->kind != 1 || c->s != s) {
      continue;
    }
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type != MOQFETCH_T_FETCH || n++ != which) {
      continue;
    }
    if (moqver_caps(mtst_ver(s)) & MOQVER_CAP_FETCH_BODY_V22) {
      CHECK(moqfetch_req22_take(body, m) == MOQCTL_OK);
    } else {
      CHECK(moqfetch_req19_take(mtst_ver(s), body, m) == MOQCTL_OK);
    }
    return (i64)c->stream_id;
  }
  return -1;
}

/* FETCHes the hub sent toward s. */
static usz mupf_n_up(wired_wt_session* s) {
  moqfetch_req m;
  usz          n = 0;
  while (mupf_up(s, n, &m) >= 0) {
    n++;
  }
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
static u8           mupf_buf[2 * WIRED_SRVLOOP_WT_BUF_CAP];
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
  static u8    pl[40000];
  moqfetch_obj ob = {0};
  for (usz i = 0; i < n; i++) {
    pl[i] = first;
  }
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
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    n += mtst_hub.fetches[i].in_use != 0;
  }
  return n;
}

/* The stream id of B's last fetch stream; ~0 if none. */
static u64 mupf_fetch_sid(void) {
  u64 sid = ~(u64)0;
  for (usz i = 0; i < g_n_calls; i++) {
    if (mf_opens(&g_calls[i])) {
      sid = g_calls[i].stream_id;
    }
  }
  return sid;
}

/* 1 iff the hub ended B's stream sid with a bare FIN. */
static int mupf_bare_fin(u64 sid) {
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind == 6 && g_calls[i].s == SESS_B &&
        g_calls[i].stream_id == sid) {
      return 1;
    }
  }
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
    if (c->s != SESS_B || c->stream_id != mf_req_sid) {
      continue;
    }
    if (c->kind != 12 && c->kind != 3) {
      continue;
    }
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type == MOQFETCH_T_FETCH_OK) {
      CHECK(moqfetch_ok_take(mtst_ver(SESS_B), body, ok) == MOQCTL_OK);
    }
    if (type == MOQCTL_T_REQUEST_ERROR) {
      CHECK(moqctl_request_error_take(body, &boff, e) == MOQCTL_OK);
    }
    return type;
  }
  return 0;
}

/* Hub ops on s's stream sid: "RST<code>|", "STOP<code>|", "FIN|". */
static const char* mupf_log(wired_wt_session* s, u64 sid) {
  mrdv_at = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    if (c->s != s || c->stream_id != sid) {
      continue;
    }
    if (c->kind == 6) {
      mrdv_put("FIN|");
    }
    if (c->kind == 7) {
      mrdv_put("RST");
    }
    if (c->kind == 13) {
      mrdv_put("STOP");
    }
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
  while (got[i] && got[i] == want[i]) {
    i++;
  }
  if (got[i] != want[i]) {
    printf("  log got \"%s\" want \"%s\"\n", got, want);
  }
  return got[i] == want[i];
}

/* ===================== GOAWAY'd peers are not asked ===================== */

/* draft-22 9.2: a peer that sent the hub a GOAWAY is sent no new request
 * -- not even the hub's upstream SUBSCRIBE. The hub's own GOAWAY does not
 * stop it from asking (the sender only SHOULD avoid it). */
static void mupf_upsub_goaway(int recv) {
  mups_init();
  wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  a->sess.goaway_recv   = recv;
  a->sess.goaway_sent   = !recv;
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mups_n_up(SESS_A) == (usz)!recv);
}

static void test_moqtrun_upfetch_upsub_skips_goaway(void) {
  mupf_upsub_goaway(1);
  mupf_upsub_goaway(0);
}

/* After a hub-wide drain, a subscription whose publisher goes away still
 * moves to another announcer. */
static void test_moqtrun_upfetch_drain_failover(void) {
  mrp_init();
  mrp_announce(SESS_B);
  CHECK(wired_moqt_goaway(&mtst_hub, mtst_z(""), 500) > 0);
  mrp_end(MRP_GA);
  CHECK(mups_n_up(SESS_B) == 1);
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
  for (usz i = 0; i < g_n_calls; i++) {
    CHECK(
        !(g_calls[i].s == SESS_B && g_calls[i].payload_len &&
          g_calls[i].payload[0] == MOQFETCH_T_FETCH_OK));
  }
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
    if (c->s != SESS_B || c->stream_id != mf_req_sid) {
      continue;
    }
    if (c->kind != 12 && c->kind != 3) {
      continue;
    }
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
  for (usz i = 0; i < f.name.n; i++) {
    r->name[i] = f.name.p[i];
  }
  r->in_use = 1;
  r->repath = 1;
  r->wt     = SESS_D;
  r->tried  = moqtrun_rp_bit(&mtst_hub, s);
}

/* d22 7.6 / 9.2: an owner that may not be asked -- one that sent the hub
 * a GOAWAY, being closed by the hub, the requester itself, or one whose
 * WebTransport session is draining (as good as its GOAWAY) -- leaves
 * the FETCH to a covering announcer (C), never to the excluded one. */
static void mupf_owner_excluded(int how) {
  wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  wired_wt_session*   s = how == 2 ? SESS_A : SESS_B;
  mupf_init();
  mupf_cache_group(3, 1);
  a->sess.goaway_recv = how == 0;
  a->closing          = how == 1;
  if (how == 3) {
    wired_moqt_on_session_draining(&mtst_hub, SESS_A);
  }
  mupf_fetch_on(s, mf_track(), mupf_rl(1, 0, 3, 0), 0);
  CHECK(mupf_n_up(SESS_A) == 0 && mupf_n_up(SESS_C) == 1);
}

static void test_moqtrun_upfetch_owner_excluded(void) {
  for (int how = 0; how < 4; how++) {
    int fails = wired_test_fails;
    mupf_owner_excluded(how);
    if (wired_test_fails != fails) {
      printf("  ^ exclusion %d\n", how);
    }
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

/* d22 9.12: a FETCH_OK whose End lies before the requested Start closes
 * the announcer's session PROTOCOL_VIOLATION, for a track the hub does
 * not hold too. */
static void test_moqtrun_upfetch_no_track_bad_end(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(2, 0, 5, 0), 0);
  i64 sid = mupf_up(SESS_C, 0, &m);
  mupf_up_ok_p(SESS_C, sid, mf_loc(1, 0), 0, wired_span_of(0, 0));
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  CHECK(
      c && c->s == SESS_C &&
      c->stream_id == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
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
  for (usz i = 0; i < 3; i++) {
    mtst_hub.blob_track.name[i] = (u8) "bob"[i];
  }
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
  if (after_10) {
    mupf_obj(1, 0, 1);
  }
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
  if (how == 3) {
    mupf_up_ok(sid, 2, 1);
  }
  if (how == 1) { /* only a marker can name a Location behind the last */
    mupf_eor(MOQFETCH_EOR_UNKNOWN, 1, 5);
  } else {
    mupf_obj(how == 2 ? 3 : 2, how == 3 ? 5 : 0, 1);
  }
  mupf_send(0);
  CHECK(mupf_resumed_after_20());
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_used() == 0);
}

static void test_moqtrun_upfetch_out_of_place(void) {
  for (int how = 0; how < 4; how++) {
    int fails = wired_test_fails;
    mupf_out_of_place(how);
    if (wired_test_fails != fails) {
      printf("  ^ out of place %d\n", how);
    }
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
  if (how == 0) {
    wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MUPF_DATA_SID, 1, 0);
  }
  if (how == 1) {
    wired_moqt_on_stream_data(
        &mtst_hub, SESS_A, (u64)sid, wired_span_of(goaway, 4), 0);
  }
  if (how == 2) {
    wired_moqt_on_session_close(&mtst_hub, SESS_A);
  }
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
    if (wired_test_fails != fails) {
      printf("  ^ leg end %d\n", how);
    }
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

/* d22 3.2.3: an upstream End short of the span leaves the rest of the
 * span to the cache side, which lacks it: Unknown through group 2, then
 * the cached groups, each once. */
static void test_moqtrun_upfetch_short_end(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_cache_group(4, 1);
  mupf_fetch(mupf_rl(1, 0, 4, 0), 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  mupf_up_ok(sid, 1, 2);
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_obj(1, 2, 1);
  mupf_send(1);
  CHECK(mupf_read(0) && mf_n == 5 && mf_fin);
  CHECK(mf_is_obj(0, 1, 0, 1) && mf_is_obj(1, 1, 2, 1));
  CHECK(mf_is_unknown(2, 2, MOQCACHE_OBJ_ID_MAX));
  CHECK(mf_is_obj(3, 3, 0, 1) && mf_is_obj(4, 4, 0, 1));
}

/* d22 10.12.3: a range the cache knows holds no Object is the header
 * alone, sent once with its FIN -- no second FIN, the slot freed once. */
static void test_moqtrun_upfetch_empty_range_once(void) {
  mupf_init();
  mupf_cache_group(3, 2);
  mupf_cache_group(4, 2);
  mupf_fetch(mupf_rl(3, 2, 3, 9), 0);
  CHECK(moqtrun_test_count_kind(4) == 1);
  CHECK(!mupf_bare_fin(mupf_fetch_sid()));
  CHECK(mupf_n_up(SESS_A) == 0 && mupf_used() == 0);
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

/* ===================== budget and markers ===================== */

static int mupf_eor_is(usz i, u64 flags, u64 g, u64 o) {
  return i < mf_n && mf_items[i].flags == flags && mf_items[i].group == g &&
         mf_items[i].object == o;
}

/* B (draft bv) fetches {1,0}..{3,0} at clock 0, group 3 cached, with
 * FILL_TIMEOUT ft (has: present) on a silent upstream; the leg lives
 * until the budget and not a tick longer. */
static void mupf_budget(int bv, int has, u64 ft, u64 budget, u64 marker) {
  moqctl_params p = mtst_params_vi(MOQCTL_PARAM_FILL_TIMEOUT, ft);
  moqfetch_req  m = {0};
  mupf_init_v(bv);
  mupf_cache_group(3, 1);
  wired_moqt_tick(&mtst_hub, 0);
  mupf_fetch(mupf_rl(1, 0, 3, 0), has ? &p : 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  wired_moqt_tick(&mtst_hub, budget - 1);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "") && mupf_used() == 1);
  wired_moqt_tick(&mtst_hub, budget);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_read(0) && mf_n == 2 && mf_fin);
  CHECK(
      mupf_eor_is(0, marker, 2, MOQCACHE_OBJ_ID_MAX) && mf_is_obj(1, 3, 0, 1));
  CHECK(mupf_used() == 0);
}

/* d22 9.20.5: FILL_TIMEOUT bounds the leg, WIRED_MOQTRUN_UPFETCH_BUDGET_MS
 * when absent; what the cache lacks is then End of Timed-Out Range toward
 * draft-22, End of Unknown Range toward a draft without 0x20C. */
static void test_moqtrun_upfetch_budget(void) {
  mupf_budget(MOQVER_D22, 1, 200, 200, MOQFETCH_EOR_TIMED_OUT);
  mupf_budget(
      MOQVER_D22, 0, 0, WIRED_MOQTRUN_UPFETCH_BUDGET_MS,
      MOQFETCH_EOR_TIMED_OUT);
  mupf_budget(
      MOQVER_D19, 1, 5000, WIRED_MOQTRUN_UPFETCH_BUDGET_MS,
      MOQFETCH_EOR_UNKNOWN);
}

/* FILL_TIMEOUT 0: nothing is asked upstream, the gap is Timed-Out. */
static void test_moqtrun_upfetch_fill_timeout_zero(void) {
  moqctl_params p = mtst_params_vi(MOQCTL_PARAM_FILL_TIMEOUT, 0);
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), &p);
  CHECK(mupf_n_up(SESS_A) == 0 && mupf_n_up(SESS_C) == 0);
  CHECK(mupf_read(0) && mf_n == 2 && mf_fin);
  CHECK(mupf_eor_is(0, MOQFETCH_EOR_TIMED_OUT, 2, MOQCACHE_OBJ_ID_MAX));
}

/* d22 11.4.1: an upstream 0x20C is relayed as 0x10C to a draft without
 * it; an End of Range marker then an Object keep their prior-Object
 * rules downstream (11.4.2). */
static void test_moqtrun_upfetch_marker_relay(void) {
  moqfetch_req m = {0};
  mupf_init_v(MOQVER_D19);
  mupf_cache_group(3, 1);
  mupf_vers(MOQVER_D22);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  mupf_up(SESS_A, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_eor(MOQFETCH_EOR_TIMED_OUT, 1, 3);
  mupf_obj(1, 5, 1);
  mupf_eor(MOQFETCH_EOR_UNKNOWN, 2, 7);
  mupf_obj(2, 9, 1);
  mupf_send(0);
  CHECK(mupf_read(0) && mf_n == 4);
  CHECK(mupf_eor_is(0, MOQFETCH_EOR_UNKNOWN, 1, 3) && mf_is_obj(1, 1, 5, 1));
  CHECK(mupf_eor_is(2, MOQFETCH_EOR_UNKNOWN, 2, 7) && mf_is_obj(3, 2, 9, 1));
}

/* ===================== the requester goes away ===================== */

/* d22 3.2.4 / 6.4.2.3: B cancelling its FETCH, stopping its data stream
 * or closing cancels the upstream FETCH -- RESET_STREAM and STOP_SENDING
 * (CANCELLED) on the request stream, STOP_SENDING on the data stream --
 * and frees the slot; a data stream A opens for it later is stopped. */
static void mupf_requester_gone(int how) {
  moqfetch_req m   = {0};
  i64          sid = mupf_span_setup(&m);
  if (how == 0) {
    wired_moqt_on_stream_reset(&mtst_hub, SESS_B, mf_req_sid, 1, 0);
  }
  if (how == 1) {
    wired_moqt_on_stream_reset(&mtst_hub, SESS_B, mupf_fetch_sid(), 1, 0);
  }
  if (how == 2) {
    wired_moqt_on_session_close(&mtst_hub, SESS_B);
  }
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_log_is(SESS_A, MUPF_DATA_SID, "STOP1|"));
  CHECK(mupf_used() == 0);
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_send_on(SESS_A, MUPF_DATA_SID + 4, 0);
  CHECK(mupf_log_is(SESS_A, MUPF_DATA_SID + 4, "STOP1|"));
}

static void test_moqtrun_upfetch_requester_gone(void) {
  for (int how = 0; how < 3; how++) {
    int fails = wired_test_fails;
    mupf_requester_gone(how);
    if (wired_test_fails != fails) {
      printf("  ^ requester gone %d\n", how);
    }
  }
}

/* d22 9.4: a FETCH of a track the hub does not hold whose data stream B
 * stops before any FETCH_OK still gets an answer -- REQUEST_ERROR
 * INTERNAL_ERROR -- and its slot frees; one B cancels gets none. */
static void mupf_unanswered_gone(int cancel) {
  moqfetch_req         m  = {0};
  moqfetch_ok          ok = {0};
  moqctl_request_error e;
  mupf_init();
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  mupf_up(SESS_C, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_obj(0, 0, 1);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 0);
  wired_moqt_on_stream_reset(
      &mtst_hub, SESS_B, cancel ? mf_req_sid : mupf_fetch_sid(), 1, 0);
  CHECK(
      cancel ? mupf_reply(&ok, &e) == 0
             : mupf_refused(MOQCTL_ERR_INTERNAL_ERROR));
  CHECK(mupf_used() == 0);
}

static void test_moqtrun_upfetch_unanswered_stop(void) {
  mupf_unanswered_gone(0);
  mupf_unanswered_gone(1);
}

/* d22 3.2.4: a data stream A opens for an upstream FETCH the hub already
 * cancelled is asked to stop (CANCELLED), never bound to it. */
static void test_moqtrun_upfetch_late_data_stream(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, mf_req_sid, 1, 0);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_send(0);
  CHECK(mupf_log_is(SESS_A, MUPF_DATA_SID, "STOP1|"));
}

/* A session gone takes its streams' bindings with it: a session that
 * rejoins under the same handle reuses stream ids from scratch. */
static void test_moqtrun_upfetch_rejoin_unbinds(void) {
  moqctl_ftn   f = mf_track();
  moqfetch_req m = {0};
  mupf_span_setup(&m);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  mf_ctrl_a = mtst_join(SESS_A);
  mtst_publish(SESS_A, mf_ctrl_a, &f, MF_ALIAS);
  usz used   = mtst_hub.cache.used;
  mf_pub_sid = MUPF_DATA_SID - 4;
  mf_obj_on(7, 0, 1, 1); /* on MUPF_DATA_SID again */
  CHECK(mtst_hub.cache.used > used);
}

/* A first delivery cut inside the FETCH_HEADER is held until the next
 * completes it, then routed to its FETCH like any other. */
static void test_moqtrun_upfetch_torn_header(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  mupf_up(SESS_A, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPF_DATA_SID, wired_span_of(mupf_buf, 1), 0);
  CHECK(mupf_log_is(SESS_A, MUPF_DATA_SID, ""));
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPF_DATA_SID, wired_span_of(mupf_buf + 1, mupf_n - 1),
      0);
  CHECK(mupf_read(0) && mf_n == 1 && mf_is_obj(0, 1, 0, 1));
}

/* A cut FETCH_HEADER that cannot be held (another already waits) cannot
 * be routed: A's upstream FETCH still waiting for its data stream is
 * cancelled at once and the cache serves the range, instead of the leg
 * stalling until its budget runs out. */
static void test_moqtrun_upfetch_torn_header_unheld(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  mupf_hdr(m.request_id, 0);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPF_DATA_SID + 4, wired_span_of(mupf_buf, 1), 0);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPF_DATA_SID, wired_span_of(mupf_buf, 1), 0);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_read(0) && mf_fin && mf_n == 2);
  CHECK(mf_is_unknown(0, 2, MOQCACHE_OBJ_ID_MAX) && mf_is_obj(1, 3, 0, 1));
}

/* An Object torn across deliveries reaches B whole. */
static void test_moqtrun_upfetch_torn_object(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  mupf_up(SESS_A, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 8);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPF_DATA_SID, wired_span_of(mupf_buf, mupf_n - 3), 0);
  CHECK(!mf_read());
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPF_DATA_SID, wired_span_of(mupf_buf + mupf_n - 3, 3),
      0);
  CHECK(mupf_read(0) && mf_n == 1 && mf_is_obj(0, 1, 0, 8));
}

/* ===================== Malformed Track ===================== */

/* The reset code the hub gave B's last fetch stream; ~0 if none. */
static u64 mupf_reset_code(void) {
  u64 sid = mupf_fetch_sid();
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind == 7 && g_calls[i].s == SESS_B &&
        g_calls[i].stream_id == sid) {
      return (u64)g_calls[i].fin;
    }
  }
  return ~(u64)0;
}

/* The status of the PUBLISH_DONE s got on its control stream; ~0 if
 * none. */
static u64 mupf_done_in(wired_span all) {
  usz        off = 0, at = 1;
  u64        t = 0;
  wired_span body;
  while (off < all.n && at != off) {
    usz                 boff = 0;
    moqctl_publish_done d;
    at = off;
    moqctl_peek_type(all, &off, &t, &body);
    if (t == MOQCTL_T_PUBLISH_DONE &&
        moqctl_publish_done_take(body, &boff, &d) == MOQCTL_OK) {
      return d.status_code;
    }
  }
  return ~(u64)0;
}

static u64 mupf_done_status(wired_wt_session* s) {
  u64 st = ~(u64)0;
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].s == s && (g_calls[i].kind == 3 || g_calls[i].kind == 12) &&
        st == ~(u64)0) {
      st = mupf_done_in(
          wired_span_of(g_calls[i].payload, g_calls[i].payload_len));
    }
  }
  return st;
}

/* d22 12.1 #5: past the final Object FETCH_OK's End Of Track named --
 * neither relayed nor cached; B's fetch is reset MALFORMED_TRACK, and the
 * held track ends for its subscribers with PUBLISH_DONE MALFORMED_TRACK. */
static void test_moqtrun_upfetch_malformed_past_end(void) {
  moqctl_ftn   f = mf_track();
  moqfetch_req m = {0};
  mupf_init();
  mtst_join(SESS_D);
  mtst_subscribe_p(SESS_D, MTRQ_S1, &f, mtst_rid += 2, 0);
  mupf_cache_group(3, 1);
  mupf_cache_group(4, 1);
  mupf_fetch(mupf_rl(1, 0, 4, 0), 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  mupf_up_ok_p(SESS_A, sid, mf_loc(2, 1), 1, wired_span_of(0, 0));
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_obj(2, 2, 1);
  usz cached = mtst_hub.cache.used;
  mupf_send(0);
  CHECK(mupf_read(0) && mf_n == 1 && mf_is_obj(0, 1, 0, 1));
  CHECK(mupf_reset_code() == MOQTRUN_RESET_MALFORMED_TRACK);
  CHECK(mtst_hub.cache.used <= cached); /* {2,2} never cached */
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_done_status(SESS_D) == MOQCTL_DONE_MALFORMED_TRACK);
  CHECK(mupf_used() == 0);
}

/* d22 12.1 #6: the cache holds {2,0} and the upstream sends {2,0} with
 * another payload: Malformed, never relayed. */
static void test_moqtrun_upfetch_malformed_conflict(void) {
  moqfetch_req m = {0};
  mupf_init();
  wired_moqt_cache_attach(&mtst_hub, mupf_arena, 3 * MOQCACHE_HDR + 4);
  mf_obj(2, 0, 1);
  mf_obj(3, 0, 100); /* too big: group 3 is a tombstone */
  mf_obj(4, 0, 1);
  mupf_fetch(mupf_rl(1, 0, 4, 0), 0);
  CHECK(mupf_up(SESS_A, 0, &m) >= 0 && m.range.end_group == 3);
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_obj_b(2, 0, 1, 0x77);
  mupf_send(0);
  CHECK(mupf_read(0) && mf_n == 1 && mf_is_obj(0, 1, 0, 1));
  CHECK(mupf_reset_code() == MOQTRUN_RESET_MALFORMED_TRACK);
}

/* d22 12.1: a conflicting Object from an announcer that does not own the
 * track (C, the owner A having sent GOAWAY) resets that fetch
 * MALFORMED_TRACK, but A's track lives on for its subscribers. */
static void test_moqtrun_upfetch_malformed_not_owner(void) {
  moqfetch_req        m = {0};
  wired_moqtrun_peer* a;
  mupf_init();
  a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  mupf_cache_group(2, 1);
  a->sess.goaway_recv = 1;
  mupf_fetch(mupf_rl(1, 0, 2, 0), 0);
  CHECK(mupf_up(SESS_C, 0, &m) >= 0);
  mupf_hdr(m.request_id, 0);
  mupf_obj_b(2, 0, 1, 0x77);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 0);
  CHECK(mupf_reset_code() == MOQTRUN_RESET_MALFORMED_TRACK);
  CHECK(a->tracks[0].in_use && !a->tracks[0].malformed);
}

/* A relayed Object is not kept, so a conflicting repeat of one is caught
 * as out of place: the leg ends, the cache side goes on, no Malformed. */
static void test_moqtrun_upfetch_repeat_of_relayed(void) {
  moqfetch_req m = {0};
  mupf_span_setup(&m);
  mupf_obj_b(2, 0, 1, 0x77);
  mupf_send(0);
  CHECK(mupf_resumed_after_20() && mupf_reset_code() == ~(u64)0);
}

/* d22 12.1 #4: past the final Object of a Group whose END_OF_GROUP the
 * held track saw is Malformed too. */
static void test_moqtrun_upfetch_malformed_group_end(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  wired_moqtrun_track* t =
      moqtrun_pubst_track(&mtst_hub, mtst_hub.cache_tag_next);
  CHECK(t != 0);
  if (!t) {
    return;
  }
  t->group_end = mf_loc(2, 0);
  t->end_flags |= 2;
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  mupf_up(SESS_A, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_obj(2, 0, 1);
  mupf_obj(2, 1, 1);
  mupf_send(0);
  CHECK(mupf_read(0) && mf_n == 1);
  CHECK(mupf_reset_code() == MOQTRUN_RESET_MALFORMED_TRACK);
}

/* d22 12.1: Malformed on one leg resets every other fetch of that track
 * from that publisher MALFORMED_TRACK and cancels its upstream FETCH --
 * here two FETCHes of a track the hub does not hold, both to C. */
static void test_moqtrun_upfetch_malformed_siblings(void) {
  moqfetch_req m0 = {0}, m1 = {0};
  mupf_init();
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  i64 s0 = mupf_up(SESS_C, 0, &m0);
  i64 s1 = mupf_up(SESS_C, 1, &m1);
  mupf_up_ok_p(SESS_C, s0, mf_loc(1, 0), 1, wired_span_of(0, 0));
  mupf_up_ok_p(SESS_C, s1, mf_loc(1, 0), 1, wired_span_of(0, 0));
  mupf_hdr(m1.request_id, 0);
  mupf_obj(0, 0, 1);
  mupf_send_on(SESS_C, MUPF_DATA_SID + 4, 0);
  mupf_hdr(m0.request_id, 0);
  mupf_obj(2, 0, 1);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 0);
  CHECK(mupf_log_is(SESS_C, (u64)s0, "RST1|STOP1|"));
  CHECK(mupf_log_is(SESS_C, (u64)s1, "RST1|STOP1|"));
  CHECK(mupf_used() == 0);
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    n += g_calls[i].kind == 7 && g_calls[i].s == SESS_B &&
         g_calls[i].fin == MOQTRUN_RESET_MALFORMED_TRACK;
  }
  CHECK(n == 2);
}

/* d22 9.4: a sibling still awaiting its FETCH_OK when another leg turns
 * Malformed is answered REQUEST_ERROR INTERNAL_ERROR, not left open. */
static void test_moqtrun_upfetch_malformed_unanswered(void) {
  moqfetch_req m0 = {0};
  mupf_init();
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  i64 s0 = mupf_up(SESS_C, 0, &m0);
  mupf_up_ok_p(SESS_C, s0, mf_loc(1, 0), 1, wired_span_of(0, 0));
  mupf_hdr(m0.request_id, 0);
  mupf_obj(2, 0, 1);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 0);
  CHECK(mupf_refused(MOQCTL_ERR_INTERNAL_ERROR));
  CHECK(mupf_used() == 0);
}

/* ===================== Objects torn across deliveries ===================== */

/* B's fetch stream items as the hub wrote them, uncut (the recording io
 * keeps only a prefix of each write). */
static u8  mupf_cap[2 * WIRED_SRVLOOP_WT_BUF_CAP];
static usz mupf_cap_n;
static int (*mupf_cap_next)(wired_wt_session*, u64, wired_span, int);
/* Where mupf_cap_is reads the captured items next. */
static usz          mupf_cap_off;
static moqfetch_seq mupf_cap_seq;

static int mupf_cap_send(wired_wt_session* s, u64 sid, wired_span p, int fin) {
  int r = mupf_cap_next(s, sid, p, fin);
  if (r <= 0 || s != SESS_B || sid != mupf_fetch_sid()) {
    return r;
  }
  CHECK(mupf_cap_n + p.n <= sizeof mupf_cap);
  for (usz i = 0; i < p.n && mupf_cap_n < sizeof mupf_cap; i++) {
    mupf_cap[mupf_cap_n++] = p.p[i];
  }
  return r;
}

/* A FETCH of groups 1..3 (3 cached) whose upstream FETCH to A is sid;
 * B's writes are captured from here on. */
static i64 mupf_big_setup(moqfetch_req* m) {
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  mupf_cap_n                 = 0;
  mupf_cap_off               = 0;
  mupf_cap_seq               = (moqfetch_seq){0};
  mupf_cap_seq.eor_timed_out = 1;
  mupf_cap_next              = mtst_hub.io.stream_send;
  mtst_hub.io.stream_send    = mupf_cap_send;
  i64 sid                    = mupf_up(SESS_A, 0, m);
  mupf_hdr(m->request_id, 0);
  return sid;
}

/* A sends the built bytes in two deliveries, the first cut at cut. */
static void mupf_send_cut(usz cut, int fin) {
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPF_DATA_SID, wired_span_of(mupf_buf, cut), 0);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPF_DATA_SID,
      wired_span_of(mupf_buf + cut, mupf_n - cut), fin);
}

/* A delivers built bytes [from, to). */
static void mupf_deliver(usz from, usz to, int fin) {
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MUPF_DATA_SID,
      wired_span_of(mupf_buf + from, to - from), fin);
}

/* The next Object B got whole is {g, o} of n bytes, its first and last
 * b. */
static int mupf_cap_is(u64 g, u64 o, usz n, u8 b) {
  moqfetch_obj ob;
  if (moqfetch_obj_take(
          wired_span_of(mupf_cap, mupf_cap_n), &mupf_cap_off, &mupf_cap_seq,
          &ob) != MOQCTL_OK) {
    return 0;
  }
  return ob.group == g && ob.object == o && ob.payload.n == n &&
         ob.payload.p[0] == b && ob.payload.p[n - 1] == b;
}

/* A small Object torn mid-payload is held whole until it is in, so a
 * refused write of it leaves nothing half-sent: the cache side serves
 * from the cursor and B's stream is not reset. */
static void test_moqtrun_upfetch_torn_small_refused(void) {
  moqfetch_req m   = {0};
  i64          sid = mupf_big_setup(&m);
  mupf_obj(1, 0, 8);
  mupf_deliver(0, mupf_n - 3, 0);
  CHECK(mupf_cap_n == 0);
  g_stream_send_reject_n = 1;
  mupf_deliver(mupf_n - 3, mupf_n, 0);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
  CHECK(mupf_reset_code() == ~(u64)0);
  CHECK(mupf_read(0) && mf_n == 2 && mf_fin);
  CHECK(mf_is_unknown(0, 2, MOQCACHE_OBJ_ID_MAX) && mf_is_obj(1, 3, 0, 1));
}

/* A large Object whose payload the transport refuses mid-way keeps its
 * place: the next tick writes the rest out, then what followed it, and
 * the upstream FIN and FETCH_OK that came meanwhile end the leg after. */
static void test_moqtrun_upfetch_large_refused_retry(void) {
  moqfetch_req m   = {0};
  i64          sid = mupf_big_setup(&m);
  mupf_obj_b(1, 0, 40000, 0x5A);
  mupf_obj(1, 1, 1);
  mupf_deliver(0, 20000, 0);
  g_stream_send_reject_n = 1;
  mupf_deliver(20000, mupf_n, 1);
  mupf_up_ok(sid, 1, 1);
  CHECK(mupf_reset_code() == ~(u64)0 && mupf_used() == 1);
  wired_moqt_tick(&mtst_hub, mtst_hub.live.last_now_ms + 1);
  CHECK(mupf_cap_is(1, 0, 40000, 0x5A) && mupf_cap_is(1, 1, 1, 0x11));
  CHECK(mupf_reset_code() == ~(u64)0 && mupf_used() == 0);
}

/* An Object cut inside its Payload Length (back 1) or right after its
 * head (back 0) reaches B whole, held (n 100) or passed through (n
 * 40000). */
static void mupf_cut_at_head(usz n, usz back) {
  moqfetch_req m = {0};
  mupf_big_setup(&m);
  mupf_obj_b(1, 0, n, 0x5A);
  mupf_send_cut(mupf_n - n - back, 0);
  CHECK(mupf_cap_is(1, 0, n, 0x5A) && mupf_cap_off == mupf_cap_n);
}

static void test_moqtrun_upfetch_cut_at_head(void) {
  mupf_cut_at_head(100, 0);
  mupf_cut_at_head(100, 1);
  mupf_cut_at_head(40000, 0);
  mupf_cut_at_head(40000, 1);
}

/* A head held at its limit, then a full delivery: the head goes out
 * wider than upstream's (every field written), the payload after it
 * unchanged. */
static void test_moqtrun_upfetch_wide_head(void) {
  static u8    props[16378] = {0x0D, 0x40 | (16375 >> 8), 16375 & 0xFF};
  static u8    pl[50000];
  moqfetch_req m  = {0};
  moqfetch_obj ob = {0};
  mupf_big_setup(&m);
  mupf_obj(1, 0, 1);
  usz at = mupf_n;
  for (usz i = 0; i < sizeof pl; i++) {
    pl[i] = 0x5A;
  }
  ob.flags     = MOQFETCH_F_PROPS;
  ob.group     = 1;
  ob.object    = 1;
  ob.has_props = 1;
  ob.props     = wired_span_of(props, sizeof props);
  ob.payload   = wired_span_of(pl, sizeof pl);
  mupf_put(&ob);
  CHECK(mupf_n - at - sizeof pl == WIRED_MOQTRUN_RELAY_FRAG_MAX);
  at += WIRED_MOQTRUN_RELAY_FRAG_MAX - 1;
  mupf_deliver(0, at, 0);
  mupf_deliver(at, at + WIRED_SRVLOOP_WT_BUF_CAP, 0);
  mupf_deliver(at + WIRED_SRVLOOP_WT_BUF_CAP, mupf_n, 0);
  CHECK(mupf_cap_is(1, 0, 1, 0x10) && mupf_cap_is(1, 1, sizeof pl, 0x5A));
  CHECK(mupf_cap_off == mupf_cap_n);
}

/* d22 7.8: an Object larger than any held tail, torn mid-payload, is
 * passed through as it arrives -- B gets it whole, and the leg goes on. */
static void test_moqtrun_upfetch_large_object(void) {
  moqfetch_req m   = {0};
  i64          sid = mupf_big_setup(&m);
  moqfetch_seq seq = {0};
  moqfetch_obj o;
  usz          off = 0;
  mupf_obj_b(1, 0, 40000, 0x5A);
  mupf_send_cut(20000, 0);
  CHECK(mupf_log_is(SESS_A, (u64)sid, ""));
  seq.eor_timed_out = 1;
  CHECK(
      moqfetch_obj_take(wired_span_of(mupf_cap, mupf_cap_n), &off, &seq, &o) ==
      MOQCTL_OK);
  CHECK(o.group == 1 && o.object == 0 && o.payload.n == 40000);
  CHECK(o.payload.n && o.payload.p[0] == 0x5A && o.payload.p[39999] == 0x5A);
  CHECK(off == mupf_cap_n);
}

/* A leg that ends inside an Object it was passing through cannot hand
 * over to the cache mid-Object: B's stream is reset INTERNAL_ERROR. */
static void test_moqtrun_upfetch_leg_ends_mid_object(void) {
  moqfetch_req m = {0};
  mupf_big_setup(&m);
  mupf_obj_b(1, 0, 40000, 0x5A);
  mupf_n -= 100;
  mupf_send_cut(20000, 1);
  CHECK(mupf_reset_code() == MOQTRUN_RESET_INTERNAL_ERROR);
  CHECK(mupf_used() == 0);
}

/* d22 12.1: the tail of a torn Object that differs from the cached copy
 * is Malformed too. */
static void test_moqtrun_upfetch_torn_conflict(void) {
  moqfetch_req m = {0};
  mupf_init();
  wired_moqt_cache_attach(&mtst_hub, mupf_arena, 3 * MOQCACHE_HDR + 8);
  mf_obj(2, 0, 4);
  mf_obj(3, 0, 100); /* too big: group 3 is a tombstone */
  mf_obj(4, 0, 1);
  mupf_fetch(mupf_rl(2, 0, 4, 0), 0);
  CHECK(mupf_up(SESS_A, 0, &m) >= 0);
  mupf_hdr(m.request_id, 0);
  mupf_obj_b(2, 0, 4, 0x20);
  mupf_buf[mupf_n - 1] = 0x77;
  mupf_send_cut(mupf_n - 2, 0);
  CHECK(mupf_reset_code() == MOQTRUN_RESET_MALFORMED_TRACK);
}

/* ===================== Mandatory Track Properties ===================== */

/* One Track Property of type 0x4000 (Mandatory, d22 3.7). */
static wired_span mupf_mand(void) {
  static u8 b[16];
  usz       n    = 0;
  u64       prev = 0;
  moqkvp    kv   = {0};
  kv.type        = 0x4000;
  kv.num         = 1;
  CHECK(moqkvp_put(wired_mspan_of(b, sizeof b), &n, &prev, &kv));
  return wired_span_of(b, n);
}

/* d22 3.7: an unknown Mandatory Track Property in FETCH_OK cancels the
 * upstream FETCH: UNSUPPORTED_EXTENSION while B is unanswered, B's stream
 * reset once data went out, else the cache side. */
static void test_moqtrun_upfetch_mandatory(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  i64 sid = mupf_up(SESS_C, 0, &m);
  mupf_up_ok_p(SESS_C, sid, mf_loc(1, 0), 0, mupf_mand());
  CHECK(mupf_refused(MOQCTL_ERR_UNSUPPORTED_EXTENSION));
  CHECK(mupf_log_is(SESS_C, (u64)sid, "RST1|STOP1|") && mupf_used() == 0);
  sid = mupf_span_setup(&m);
  mupf_up_ok_p(SESS_A, sid, mf_loc(2, 0), 0, mupf_mand());
  CHECK(mupf_reset_code() == MOQTRUN_RESET_INTERNAL_ERROR);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|") && mupf_used() == 0);
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  sid = mupf_up(SESS_A, 0, &m);
  mupf_up_ok_p(SESS_A, sid, mf_loc(2, 0), 0, mupf_mand());
  CHECK(mupf_read(0) && mf_n == 2 && mf_fin);
  CHECK(mf_is_unknown(0, 2, MOQCACHE_OBJ_ID_MAX) && mf_is_obj(1, 3, 0, 1));
}

/* ===================== the track owner leaves ===================== */

/* Calls the hub made toward s from call index from on. */
static usz mupf_calls_to(wired_wt_session* s, usz from) {
  usz n = 0;
  for (usz i = from; i < g_n_calls; i++) {
    n += g_calls[i].s == s;
  }
  return n;
}

/* A fill of alice from group 1 (group 3 cached): its upstream FETCH is in
 * flight to A; returns the fill's Request ID. */
static u64 mupf_fill_setup(moqfetch_req* m) {
  moqfetch_fill fill = {0};
  mupf_init();
  mupf_cache_group(3, 1);
  fill.has_filter        = 1;
  fill.range.sk          = MOQCTL_RSK_ABS;
  fill.range.start_group = 1;
  fill.range.ek          = MOQCTL_REK_UNBOUNDED;
  u64 rid                = mfill_subscribe(&fill, 0);
  mupf_up(SESS_A, 0, m);
  return rid;
}

/* The owner's session closes during the leg (d22 3.4.1): nothing more
 * goes toward it, and a fill -- relaying already or not opened yet --
 * is reset INTERNAL_ERROR at once (never a Timed-Out FIN), its upstream
 * FETCH let go first, so it holds no PUBLISH_DONE back. */
static void mupf_owner_gone_fill(int relayed) {
  moqfetch_req m   = {0};
  u64          rid = mupf_fill_setup(&m);
  CHECK(!moqtrun_fetch_blocked(&mtst_hub.fetches[0]));
  if (relayed) {
    mupf_hdr(m.request_id, 0);
    mupf_obj(1, 0, 1);
    mupf_send(0);
  }
  usz before = g_n_calls;
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mupf_calls_to(SESS_A, before) == 0);
  CHECK(mupf_reset_code() == MOQTRUN_RESET_INTERNAL_ERROR);
  CHECK(!moqtrun_fill_held_for(&mtst_hub, SESS_B, rid));
  CHECK(mupf_used() == 0);
}

static void test_moqtrun_upfetch_owner_gone_fill(void) {
  mupf_owner_gone_fill(1);
  mupf_owner_gone_fill(0);
}

/* A FETCH whose leg went to the leaving owner reads the released cache
 * as Unknown to its End, then FIN; nothing more goes toward the owner. */
static void test_moqtrun_upfetch_owner_gone_fetch(void) {
  moqfetch_req m = {0};
  mupf_span_setup(&m);
  usz before = g_n_calls;
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mupf_calls_to(SESS_A, before) == 0);
  CHECK(mupf_read(0) && mf_n == 3 && mf_fin);
  CHECK(mf_is_obj(1, 2, 0, 1) && mf_is_unknown(2, 4, 0));
  CHECK(mupf_used() == 0);
}

/* Live Objects evicting a cached group while the leg runs: the cache side
 * reports it Unknown, nothing twice. */
static void test_moqtrun_upfetch_evicted_during_leg(void) {
  moqfetch_req m = {0};
  mupf_init();
  wired_moqt_cache_attach(&mtst_hub, mupf_arena, 2 * (MOQCACHE_HDR + 1));
  mupf_cache_group(3, 1);
  mupf_cache_group(4, 1);
  mupf_fetch(mupf_rl(1, 0, 4, 0), 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  mf_obj(5, 0, 1); /* evicts group 3 */
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_obj(2, 0, 1);
  mupf_send(0);
  mupf_up_ok(sid, 2, MOQFETCH_OBJ_GROUP_END);
  mupf_send(1);
  CHECK(mupf_read(0) && mf_n == 4 && mf_fin);
  CHECK(mf_is_obj(0, 1, 0, 1) && mf_is_obj(1, 2, 0, 1));
  CHECK(mf_is_unknown(2, 3, MOQCACHE_OBJ_ID_MAX) && mf_is_obj(3, 4, 0, 1));
}

/* ===================== Range Filters ===================== */

/* d22 3.3.2: the FETCH's Range Filter goes upstream byte for byte, and a
 * gap the publisher leaves unmarked is relayed unmarked. */
static void test_moqtrun_upfetch_range_filter(void) {
  moqctl_rangefilter  rf = mtst_rngf1(0, 0, 4, 1);
  moqctl_params       p  = {0};
  moqfetch_req        m  = {0};
  const moqctl_param* up;
  mtst_rngf_param(&p, MOQCTL_PARAM_OBJECTID_FILTER, &rf);
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 3, 0), &p);
  CHECK(mupf_up(SESS_A, 0, &m) >= 0);
  up = moqctl_params_find(&m.params, MOQCTL_PARAM_OBJECTID_FILTER);
  CHECK(up && up->bytes.n == p.items[0].bytes.n);
  CHECK(up && !ct_diffn(up->bytes.p, p.items[0].bytes.p, up->bytes.n));
  mupf_hdr(m.request_id, 0);
  mupf_obj(1, 0, 1);
  mupf_obj(1, 3, 1);
  mupf_send(0);
  CHECK(mupf_read(0) && mf_n == 2);
  CHECK(mf_is_obj(0, 1, 0, 1) && mf_is_obj(1, 1, 3, 1));
}

/* ===================== malformed upstream bytes ===================== */

/* A FETCH_OK that does not decode closes A PROTOCOL_VIOLATION (only A);
 * B gets the cache side. */
static void test_moqtrun_upfetch_bad_reply_bytes(void) {
  static const u8 bad[] = {0x18, 0x00, 0x01, 0xFF}; /* FETCH_OK, cut */
  moqfetch_req    m     = {0};
  i64             sid   = mupf_span_setup(&m);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, (u64)sid, wired_span_of(bad, sizeof bad), 0);
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  CHECK(c && c->s == SESS_A && moqtrun_test_count_kind(11) == 1);
  CHECK(mupf_resumed_after_20());
}

/* d22 11.4.4: a Group ID Delta below Group 0 on a Descending stream
 * closes A PROTOCOL_VIOLATION; B gets the cache side. */
static void test_moqtrun_upfetch_delta_underflow(void) {
  static const u8 under[] = {0x1C, 0x05, 0x00, 0x80, 0x00};
  moqctl_params   desc    = mtst_params_u8(MOQCTL_PARAM_GROUP_ORDER, 2);
  moqfetch_req    m       = {0};
  mupf_init_nocache();
  mupf_fetch(mupf_rl(1, 0, 2, 1), &desc);
  mupf_up(SESS_A, 0, &m);
  mupf_hdr(m.request_id, 1);
  mupf_obj(2, 0, 1);
  for (usz i = 0; i < sizeof under; i++) {
    mupf_buf[mupf_n++] = under[i];
  }
  mupf_send(0);
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  CHECK(
      c && c->s == SESS_A &&
      c->stream_id == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
  CHECK(mupf_read(1) && mf_fin && mf_is_obj(0, 2, 0, 1));
}

void test_moqtrun_upfetch(void) {
  test_moqtrun_upfetch_upsub_skips_goaway();
  test_moqtrun_upfetch_drain_failover();
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
  test_moqtrun_upfetch_no_track_bad_end();
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
  test_moqtrun_upfetch_short_end();
  test_moqtrun_upfetch_empty_answer();
  test_moqtrun_upfetch_empty_range_once();
  test_moqtrun_upfetch_budget();
  test_moqtrun_upfetch_fill_timeout_zero();
  test_moqtrun_upfetch_marker_relay();
  test_moqtrun_upfetch_requester_gone();
  test_moqtrun_upfetch_unanswered_stop();
  test_moqtrun_upfetch_late_data_stream();
  test_moqtrun_upfetch_rejoin_unbinds();
  test_moqtrun_upfetch_torn_header();
  test_moqtrun_upfetch_torn_header_unheld();
  test_moqtrun_upfetch_torn_object();
  test_moqtrun_upfetch_malformed_past_end();
  test_moqtrun_upfetch_malformed_conflict();
  test_moqtrun_upfetch_malformed_not_owner();
  test_moqtrun_upfetch_repeat_of_relayed();
  test_moqtrun_upfetch_malformed_group_end();
  test_moqtrun_upfetch_malformed_siblings();
  test_moqtrun_upfetch_malformed_unanswered();
  test_moqtrun_upfetch_large_object();
  test_moqtrun_upfetch_leg_ends_mid_object();
  test_moqtrun_upfetch_torn_conflict();
  test_moqtrun_upfetch_torn_small_refused();
  test_moqtrun_upfetch_large_refused_retry();
  test_moqtrun_upfetch_cut_at_head();
  test_moqtrun_upfetch_wide_head();
  test_moqtrun_upfetch_mandatory();
  test_moqtrun_upfetch_owner_gone_fill();
  test_moqtrun_upfetch_owner_gone_fetch();
  test_moqtrun_upfetch_evicted_during_leg();
  test_moqtrun_upfetch_range_filter();
  test_moqtrun_upfetch_bad_reply_bytes();
  test_moqtrun_upfetch_delta_underflow();
}
