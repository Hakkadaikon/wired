/* Rules the hub keeps by how it is built, pinned through its production
 * path under every draft that has them. Shares the fixtures of
 * moqtrun_test.c, moqtrun_sub_test.c, moqtrun_ns_test.c,
 * moqtrun_subtracks_test.c, moqtrun_rdv_test.c, moqtrun_done_test.c,
 * moqtrun_misc_test.c and moqtrun_upsub_test.c (same unity TU). */

/* Uni streams and datagrams the hub sent s: the Objects it relayed. */
static usz mtbc_objs_to(wired_wt_session* s) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    int k = g_calls[i].kind;
    n += g_calls[i].s == s && (k == 4 || k == 5 || k == 8 || k == 9);
  }
  return n;
}

/* Header (Type 0x30, Track Alias alias, Group 1) + one Object, FINed, on
 * A's uni stream sid. */
static void mtbc_group(u64 sid, u64 alias) {
  u8             buf[64];
  u8             b   = 'o';
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x30;
  h.track_alias      = alias;
  h.group_id         = 1;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  moqdata_obj_put(
      wired_mspan_of(buf, sizeof buf), &off, 0, wired_span_of(&b, 1));
  mt_feed(&mtst_hub, SESS_A, sid, wired_span_of(buf, off), 1);
}

/* draft-23 6.4.2.1 (draft-22 6.4.2.1, draft-18/19 10.1): the server's
 * Request IDs are odd, start at 1 and step by 2 -- three upstream
 * SUBSCRIBEs toward A carry 1, 3, 5. */
static void mtbc_rids(void) {
  static const char* const names[] = {"alice", "bob", "carol"};
  moqctl_subscribe         m;
  mups_init();
  for (usz i = 0; i < 3; i++) {
    moqctl_ftn f = mtst_ftn("chat", "room1", names[i]);
    mtst_subscribe_p(SESS_B, MTRQ_ID(i + 1), &f, mtst_rid += 4, 0);
  }
  for (usz i = 0; i < 3; i++) {
    CHECK(mups_up(SESS_A, i, &m) >= 0);
    CHECK(m.request_id == 1 + 2 * i);
  }
}

/* draft-22 9.7 (draft-23 9.4.2): a Redirect only with REDIRECT -- the
 * hub's DOES_NOT_EXIST carries none. */
static void mtbc_no_redirect(void) {
  moqctl_request_error e   = {0};
  usz                  off = 0, boff = 0;
  u64                  type;
  wired_span           body;
  moqctl_ftn           f = mtst_ftn("chat", "room1", "bob");
  mtrq_setup();
  mtst_subscribe(SESS_B, MTRQ_S1, &f);
  const moqtrun_test_call* c = moqtrun_test_last_kind(12);
  CHECK(c != 0);
  if (!c) {
    return;
  }
  CHECK(
      mt_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_REQUEST_ERROR);
  CHECK(
      moqctl_request_error_take_v(mtst_ver(SESS_B), body, &boff, &e) ==
      MOQCTL_OK);
  CHECK(e.error_code == MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(!e.has_redirect);
}

/* draft-22 5.1.1 (draft-18/19 5.1.1, draft-23 5.1.1): a SUBSCRIBE refused
 * REQUEST_ERROR gets no Object -- not even once A later PUBLISHes that
 * Track (alias 2) and sends a Group. */
static void mtbc_refused_sub_no_objects(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "bob");
  mtrq_setup();
  mtst_subscribe(SESS_B, MTRQ_S1, &f);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_REQUEST_ERROR);
  mtst_publish(SESS_A, MTRQ_ID(5), &f, 2);
  moqtrun_test_reset();
  mtbc_group(2002, 2);
  CHECK(mtbc_objs_to(SESS_B) == 0);
}

/* Replies the hub sent A on sid (reply_open or stream_send). */
static usz mtbc_replies_on(u64 sid) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    int k = g_calls[i].kind;
    n += g_calls[i].s == SESS_A && g_calls[i].stream_id == sid &&
         (k == 3 || k == 12);
  }
  return n;
}

/* Index of the hub's FIN of A's sid (io.stream_fin, or a send with FIN);
 * ~0 if none. */
static usz mtbc_fin_at(u64 sid) {
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    int                      fin = c->kind == 6 || (c->kind == 3 && c->fin);
    if (c->s == SESS_A && c->stream_id == sid && fin) {
      return i;
    }
  }
  return ~(usz)0;
}

/* draft-22 9.9 (draft-18/19 10.11, draft-23 9.9): PUBLISH and its
 * PUBLISH_DONE in one delivery, before any answer -- the hub still sends
 * exactly one PUBLISH reply, before its FIN of that stream. */
static void mtbc_done_before_reply(void) {
  static moqctl_publish      m;
  static moqctl_publish_done d;
  u8                         buf[2 * MTST_MSG_MAX];
  usz                        n;
  mtst_init();
  mtst_join(SESS_A);
  m.request_id  = mtst_rid += 4;
  m.name        = mtst_ftn("chat", "room1", "alice");
  m.track_alias = 1;
  d.status_code = MOQCTL_DONE_TRACK_ENDED;
  n             = moqtrun_envelope_put(
      MOQVER_D22, wired_mspan_of(buf, sizeof buf), MOQCTL_T_PUBLISH,
      mtst_enc_publish, &m);
  n += moqtrun_envelope_put(
      MOQVER_D22, wired_mspan_of(buf + n, sizeof buf - n),
      MOQCTL_T_PUBLISH_DONE, mtdn_enc_done, &d);
  moqtrun_test_reset();
  mt_feed(&mtst_hub, SESS_A, MTDN_PUB, wired_span_of(buf, n), 0);
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtbc_replies_on(MTDN_PUB) == 1);
  CHECK(mups_first(SESS_A, MTDN_PUB, 3, 12) < mtbc_fin_at(MTDN_PUB));
  CHECK(mtbc_fin_at(MTDN_PUB) != ~(usz)0);
  CHECK(mtrq_type_on(12, MTDN_PUB) == MOQCTL_T_REQUEST_OK);
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* draft-19 10.19.1 (draft-18 10.19.1, draft-22 9.8, draft-23 9.8): the
 * PUBLISH the hub sends for a SUBSCRIBE_TRACKS carries its GROUP_ORDER. */
static void mtbc_publish_group_order(void) {
  moqctl_publish got[2];
  mtmi_subtracks_fwd1_go2();
  CHECK(mtst_pub_opens(SESS_B, got, 2) == 1);
  const moqctl_param* go =
      moqctl_params_find(&got[0].params, MOQCTL_PARAM_GROUP_ORDER);
  CHECK(go != 0 && go->u8v == 2);
}

/* B's SUBSCRIBE_TRACKS "chat" with FORWARD 1 on MTRQ_S1 (draft-18's
 * default would forward nothing). */
static void mtbc_subtracks_fwd1(void) {
  static moqns_req m;
  m.request_id = mtst_rid += 4;
  m.ns         = mtns_ns("chat");
  m.params     = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  mtst_send(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE_TRACKS, mtst_enc_subtracks, &m);
}

/* A published alice; B SUBSCRIBE_TRACKS "chat", the hub's PUBLISH to B on
 * its stream (returned). */
static i64 mtbc_subtracks(void) {
  moqctl_ftn     f = mtst_ftn("chat", "room1", "alice");
  moqctl_publish got[2];
  mtst_subtracks_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtbc_subtracks_fwd1();
  CHECK(mtst_pub_opens(SESS_B, got, 2) == 1);
  return mtst_pub_stream_id(0);
}

/* draft-22 9.8 (draft-18/19 10.10, draft-23 9.8): B refuses the hub's
 * PUBLISH UNINTERESTED -- A's later Group reaches B not at all. */
static void mtbc_uninterested_no_objects(void) {
  i64 sid = mtbc_subtracks();
  mtst_pub_err(SESS_B, (u64)sid, MOQCTL_ERR_UNINTERESTED);
  mt_feed(&mtst_hub, SESS_B, (u64)sid, wired_span_of(0, 0), 1);
  moqtrun_test_reset();
  mtbc_group(2002, 1);
  CHECK(mtbc_objs_to(SESS_B) == 0);
}

/* draft-18 6.1: a FIN on B's SUBSCRIBE_TRACKS stream cancels it -- a
 * Track published afterwards gets no PUBLISH toward B; without the FIN it
 * gets one. PUBLISHes toward B. */
static usz mtbc_subtracks_d18(int fin) {
  moqctl_ftn     g = mtst_ftn("chat", "room1", "bob");
  moqctl_publish got[2];
  mtst_subtracks_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = MOQVER_D18;
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D18;
  mtbc_subtracks_fwd1();
  mt_feed(&mtst_hub, SESS_B, MTRQ_S1, wired_span_of(0, 0), fin);
  moqtrun_test_reset();
  mtst_publish(SESS_A, ca, &g, 2);
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(moqtrun_test_count_kind(11) == 0);
  return mtst_pub_opens(SESS_B, got, 2);
}

static void test_mtbc_subtracks_fin_cancels_d18(void) {
  CHECK(mtbc_subtracks_d18(0) == 1);
  CHECK(mtbc_subtracks_d18(1) == 0);
}

/* ===== implemented, now pinned ===== */

/* draft-22/23 11.5.2 (draft-18/19 11.5.2): a padding datagram
 * (0x132B3E29) is discarded -- nothing relayed, no close; the Object
 * datagram after it still reaches B. */
static void mtbc_padding_datagram(void) {
  u8  b[16];
  usz n  = moqvi_encode(b, MOQDATA_TYPE_PADDING + 1); /* 0x132B3E29 */
  b[n++] = 0xAA;
  b[n++] = 0xBB;
  mtdn_setup();
  moqtrun_test_reset();
  wired_moqt_on_datagram(&mtst_hub, SESS_A, wired_span_of(b, n));
  CHECK(g_n_calls == 0);
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  CHECK(moqtrun_test_count_kind(9) == 1);
}

/* draft-19 7.3, 10.2 (MOQT-224): B's OBJECT_DELIVERY_TIMEOUT,
 * SUBSCRIBER_PRIORITY and GROUP_ORDER stay off the upstream SUBSCRIBE. */
static void mtbc_upstream_params_own(void) {
  moqctl_ftn    f = mtst_ftn("chat", "room1", "alice");
  moqctl_params p = mtst_params_vi(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, 500);
  moqctl_subscribe m;
  p.items[1] = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 5).items[0];
  p.items[2] = mtst_params_u8(MOQCTL_PARAM_GROUP_ORDER, 2).items[0];
  p.n        = 3;
  mups_init();
  mtst_subscribe_p(SESS_B, MRDV_S1, &f, mtst_rid += 4, &p);
  CHECK(mups_up(SESS_A, 0, &m) >= 0);
  CHECK(!moqctl_params_find(&m.params, MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT));
  CHECK(!moqctl_params_find(&m.params, MOQCTL_PARAM_SUBSCRIBER_PRIORITY));
  CHECK(!moqctl_params_find(&m.params, MOQCTL_PARAM_GROUP_ORDER));
}

/* A PUBLISHes alice with the one Track Property kv: 1 iff taken. */
static int mtbc_publish_prop(const moqkvp* kv) {
  u8         buf[32];
  usz        n    = 0;
  u64        prev = 0;
  moqctl_ftn f    = mtst_ftn("chat", "room1", "alice");
  CHECK(moqkvp_put(wired_mspan_of(buf, sizeof buf), &n, &prev, kv));
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_publish_props(SESS_A, ca, &f, 1, wired_span_of(buf, n));
  CHECK(mtrq_closes() == 0);
  return moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use;
}

/* draft-19 2.5.1 (draft-18 2.5.1, draft-22/23 3.7): only 0x4000-0x7FFF
 * is Mandatory -- 0x3FFF and 0x8000, just outside, are taken. */
static void mtbc_mandatory_edges(void) {
  static const u8 raw[] = {0x01};
  moqkvp          lo    = {0};
  moqkvp          hi    = {0};
  lo.type               = 0x3FFF;
  lo.is_raw             = 1;
  lo.raw                = wired_span_of(raw, sizeof raw);
  hi.type               = 0x8000;
  hi.num                = 1;
  CHECK(mtbc_publish_prop(&lo));
  CHECK(mtbc_publish_prop(&hi));
}

/* draft-22 3.3.1 (MQ22-108a), draft-23 3.3.1: a Location Filter wholly
 * before the Largest Object is still valid -- AbsoluteStart {1, 0} after
 * Groups 1..3 is answered SUBSCRIBE_OK, not INVALID_RANGE. */
static void mtbc_filter_past_valid(void) {
  static const u8 b[] = {0x00, 0x02, 0x04, 'c',  'h',  'a',  't',  0x05,
                         'r',  'o',  'o',  'm',  '1',  0x05, 'a',  'l',
                         'i',  'c',  'e',  0x01, 0x21, 0x02, 0x01, 0x00};
  mtrq_setup();
  for (u64 g = 1; g <= 3; g++) {
    mtbc_group(2002 + 4 * g, 1);
  }
  mtrq_raw(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE, b, sizeof b);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(11) == 0);
}

static void mtbc_all(void) {
  mtbc_rids();
  mtbc_no_redirect();
  mtbc_refused_sub_no_objects();
  mtbc_done_before_reply();
  mtbc_uninterested_no_objects();
  mtbc_padding_datagram();
  mtbc_upstream_params_own();
  mtbc_mandatory_edges();
}

/* draft-18 10.2.8 admits GROUP_ORDER in no SUBSCRIBE_TRACKS: the rule
 * starts at draft-19. */
static void test_mtbc_group_order_d19_on(void) {
  static const int vers[] = {MOQVER_D23, MOQVER_D22, MOQVER_D19};
  for (usz i = 0; i < 3; i++) {
    g_moqtrun_test_ver = vers[i];
    mtbc_publish_group_order();
  }
  g_moqtrun_test_ver = MOQVER_D19;
}

void test_moqtrun_bycons(void) {
  moqtrun_test_allver(mtbc_all);
  test_mtbc_group_order_d19_on();
  test_mtbc_subtracks_fin_cancels_d18();
  moqtrun_test_vers(MOQVER_CAP_LOCFILTER_TYPED, 0, mtbc_filter_past_valid);
}
