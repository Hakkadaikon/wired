/* Hub subscription state and Full Track Name matching
 * (draft-ietf-moq-transport-19 1.5, 9.3.1, 10.2.7-10.2.17). Shares the
 * recording io stubs and fixtures of moqtrun_test.c (same unity TU). */

static wired_moqt_hub mtst_hub;
static u64            mtst_rid;

#define MTST_MSG_MAX (WIRED_MOQTRUN_CTL_MSG_MAX + WIRED_MOQTRUN_CTL_HDR_MAX)

static wired_span mtst_z(const char* z) {
  usz n = 0;
  while (z[n]) n++;
  return wired_span_of((const u8*)z, n);
}

/* Full Track Name {ns0, ns1} / name. */
static moqctl_ftn mtst_ftn(const char* ns0, const char* ns1, const char* name) {
  moqctl_ftn f   = {0};
  f.ns.fields[0] = mtst_z(ns0);
  f.ns.fields[1] = mtst_z(ns1);
  f.ns.n         = 2;
  f.name         = mtst_z(name);
  return f;
}

static int mtst_enc_publish(wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_encode(buf, off, m);
}

static int mtst_enc_subscribe(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_encode(buf, off, m);
}

static void mtst_send(
    wired_wt_session*      s,
    u64                    ctrl,
    u64                    type,
    moqtrun_body_encode_fn fn,
    const void*            m) {
  u8  buf[MTST_MSG_MAX];
  usz n = moqtrun_envelope_put(wired_mspan_of(buf, sizeof buf), type, fn, m);
  CHECK(n != 0);
  wired_moqt_on_stream_data(&mtst_hub, s, ctrl, wired_span_of(buf, n), 0);
}

static void mtst_publish_p(
    wired_wt_session*    s,
    u64                  ctrl,
    const moqctl_ftn*    f,
    u64                  alias,
    const moqctl_params* params) {
  static moqctl_publish m;
  m.request_id  = mtst_rid += 2;
  m.name        = *f;
  m.track_alias = alias;
  m.params.n    = 0;
  if (params) m.params = *params;
  mtst_send(s, ctrl, MOQCTL_T_PUBLISH, mtst_enc_publish, &m);
}

static void mtst_publish(
    wired_wt_session* s, u64 ctrl, const moqctl_ftn* f, u64 alias) {
  mtst_publish_p(s, ctrl, f, alias, 0);
}

static void mtst_subscribe_p(
    wired_wt_session*    s,
    u64                  ctrl,
    const moqctl_ftn*    f,
    u64                  rid,
    const moqctl_params* params) {
  static moqctl_subscribe m;
  m.request_id = rid;
  m.name       = *f;
  m.params.n   = 0;
  if (params) m.params = *params;
  mtst_send(s, ctrl, MOQCTL_T_SUBSCRIBE, mtst_enc_subscribe, &m);
}

static void mtst_subscribe(wired_wt_session* s, u64 ctrl, const moqctl_ftn* f) {
  mtst_subscribe_p(s, ctrl, f, mtst_rid += 2, 0);
}

static u64 mtst_join(wired_wt_session* s) {
  return moqtrun_test_join(&mtst_hub, s);
}

static void mtst_init(void) {
  moqtrun_test_reset();
  wired_moqt_init(&mtst_hub, moqtrun_test_io());
}

/* The last reply decoded as SUBSCRIBE_OK; 0 if it is anything else. */
static const moqctl_subscribe_ok* mtst_last_ok(void) {
  static moqctl_subscribe_ok ok;
  const moqtrun_test_call*   c   = moqtrun_test_last_kind(3);
  usz                        off = 0, boff = 0;
  u64                        type;
  wired_span                 body;
  if (!c) return 0;
  if (moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
      MOQCTL_OK)
    return 0;
  if (type != MOQCTL_T_SUBSCRIBE_OK) return 0;
  if (moqctl_subscribe_ok_take(body, &boff, &ok) != MOQCTL_OK) return 0;
  return &ok;
}

static const moqctl_param* mtst_largest(void) {
  const moqctl_subscribe_ok* ok = mtst_last_ok();
  CHECK(ok != 0);
  return ok ? moqctl_params_find(&ok->params, MOQCTL_PARAM_LARGEST_OBJECT) : 0;
}

static usz mtst_idx(wired_wt_session* s) {
  return (usz)(moqtrun_find_by_wt(&mtst_hub, s) - mtst_hub.peers);
}

/* The subscription s holds on publisher pub's first track. */
static wired_moqtrun_sub* mtst_sub(wired_wt_session* pub, wired_wt_session* s) {
  wired_moqtrun_track* t = &moqtrun_find_by_wt(&mtst_hub, pub)->tracks[0];
  return moqtrun_track_sub_of_peer(t, mtst_idx(s));
}

/* ===================== Full Track Name matching ===================== */

/* Same Track Name under another namespace is another track (1.5): no
 * match, DOES_NOT_EXIST; the exact Full Track Name matches. */
static void test_moqtrun_sub_ns_must_match(void) {
  mtst_init();
  u64        ca    = mtst_join(SESS_A);
  u64        cb    = mtst_join(SESS_B);
  moqctl_ftn pub   = mtst_ftn("chat", "room1", "alice");
  moqctl_ftn other = mtst_ftn("chat", "room2", "alice");
  mtst_publish(SESS_A, ca, &pub, 1);
  mtst_subscribe(SESS_B, cb, &other);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
  mtst_subscribe(SESS_B, cb, &pub);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
}

/* A namespace with the maximum MOQCTL_MAX_NS_FIELDS fields is stored
 * whole: exact match succeeds, a difference in the last field does not. */
static void test_moqtrun_sub_ns_max_fields(void) {
  static const char* const F = "abcdefghijklmnopqrstuvwxyzABCDEF";
  moqctl_ftn               f = {0};
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  for (usz i = 0; i < MOQCTL_MAX_NS_FIELDS; i++)
    f.ns.fields[i] = wired_span_of((const u8*)F + i, 1);
  f.ns.n = MOQCTL_MAX_NS_FIELDS;
  f.name = mtst_z("alice");
  mtst_publish(SESS_A, ca, &f, 1);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_OK);
  mtst_subscribe(SESS_B, cb, &f);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  f.ns.fields[MOQCTL_MAX_NS_FIELDS - 1] = mtst_z("z");
  mtst_subscribe(SESS_B, cb, &f);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
}

/* Two publishers of one Track Name under different namespaces are two
 * tracks: the newer does not supersede the older, whose Objects still
 * reach its subscriber. */
static void test_moqtrun_sub_same_name_other_ns_coexist(void) {
  mtst_init();
  u64        ca = mtst_join(SESS_A);
  u64        cc = mtst_join(SESS_C);
  u64        cb = mtst_join(SESS_B);
  moqctl_ftn r1 = mtst_ftn("chat", "room1", "alice");
  moqctl_ftn r2 = mtst_ftn("chat", "room2", "alice");
  mtst_publish(SESS_A, ca, &r1, 1);
  mtst_publish(SESS_C, cc, &r2, 1);
  mtst_subscribe(SESS_B, cb, &r1);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* A namespace longer than the hub stores (WIRED_MOQTRUN_MAX_NS) is
 * refused, never truncated into a false match. */
static void test_moqtrun_sub_ns_over_cap_refused(void) {
  static u8  big[WIRED_MOQTRUN_MAX_NS];
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  for (usz i = 0; i < sizeof big; i++) big[i] = 'x';
  f.ns.fields[1] = wired_span_of(big, sizeof big);
  mtst_publish(SESS_A, ca, &f, 1);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
}

/* ===================== subscription state ===================== */

static moqctl_params mtst_params_full(void) {
  moqctl_params p               = {0};
  p.items[0].type               = MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT;
  p.items[0].enc                = MOQCTL_PENC_VARINT;
  p.items[1].type               = MOQCTL_PARAM_FORWARD;
  p.items[1].enc                = MOQCTL_PENC_UINT8;
  p.items[1].u8v                = 1;
  p.items[2].type               = MOQCTL_PARAM_SUBSCRIBER_PRIORITY;
  p.items[2].enc                = MOQCTL_PENC_UINT8;
  p.items[2].u8v                = 7;
  p.items[3].type               = MOQCTL_PARAM_LOCATION_FILTER;
  p.items[3].enc                = MOQCTL_PENC_LOCFILTER;
  p.items[3].lf.type            = MOQCTL_FILTER_ABS_RANGE;
  p.items[3].lf.start.group     = 5;
  p.items[3].lf.start.object    = 2;
  p.items[3].lf.end_group_delta = 3;
  p.items[4].type               = MOQCTL_PARAM_GROUP_ORDER;
  p.items[4].enc                = MOQCTL_PENC_UINT8;
  p.items[4].u8v                = 2;
  p.n                           = 5;
  return p;
}

/* SUBSCRIBE's Request ID and parameters land on the subscription. */
static void test_moqtrun_sub_params_recorded(void) {
  moqctl_params p = mtst_params_full();
  moqctl_ftn    f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subscribe_p(SESS_B, cb, &f, 42, &p);
  wired_moqtrun_sub* s = mtst_sub(SESS_A, SESS_B);
  CHECK(s != 0);
  CHECK(s->request_id == 42);
  CHECK(s->has_priority == 1 && s->priority == 7);
  CHECK(s->group_order == 2);
  CHECK(s->has_delivery_timeout == 1 && s->delivery_timeout == 0);
  CHECK(s->forward_off == 0);
  CHECK(s->start.group == 5 && s->start.object == 2);
  CHECK(s->has_end_group == 1 && s->end_group == 8);
}

/* Absent parameters: draft defaults (forward, unfiltered from {0,0}, no
 * priority / group order / timeout recorded). */
static void test_moqtrun_sub_params_absent(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subscribe_p(SESS_B, cb, &f, 9, 0);
  wired_moqtrun_sub* s = mtst_sub(SESS_A, SESS_B);
  CHECK(s != 0);
  CHECK(s->request_id == 9);
  CHECK(s->has_priority == 0 && s->group_order == 0);
  CHECK(s->has_delivery_timeout == 0 && s->forward_off == 0);
  CHECK(s->start.group == 0 && s->start.object == 0);
  CHECK(s->has_end_group == 0);
}

static moqctl_params mtst_params_u8(u64 type, u8 v) {
  moqctl_params p = {0};
  p.items[0].type = type;
  p.items[0].enc  = MOQCTL_PENC_UINT8;
  p.items[0].u8v  = v;
  p.n             = 1;
  return p;
}

static moqctl_params mtst_params_filter(u64 type) {
  moqctl_params p    = {0};
  p.items[0].type    = MOQCTL_PARAM_LOCATION_FILTER;
  p.items[0].enc     = MOQCTL_PENC_LOCFILTER;
  p.items[0].lf.type = type;
  p.n                = 1;
  return p;
}

/* FORWARD 0 (10.2.17): no Objects for that subscription -- neither a
 * one-shot stream, a keep-open stream, nor a datagram -- while a
 * forwarding subscriber on the same track gets each one. */
static void test_moqtrun_sub_forward0_gets_nothing(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_ftn    f  = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  u64 cc = mtst_join(SESS_C);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subscribe_p(SESS_B, cb, &f, 2, &p0);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(mtst_sub(SESS_A, SESS_B)->forward_off == 1);
  mtst_subscribe(SESS_C, cc, &f);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_C);
  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, 1001,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);
  CHECK(moqtrun_test_count_kind(5) == 1);
  CHECK(moqtrun_test_last_kind(5)->s == SESS_C);
  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  CHECK(moqtrun_test_count_kind(9) == 1);
  CHECK(moqtrun_test_last_kind(9)->s == SESS_C);
}

/* FORWARD 0 on the hub's own blob track: SUBSCRIBE_OK, no blob sent. */
static void test_moqtrun_sub_forward0_blob_not_sent(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_ftn    f  = mtst_ftn("chat", "room1", "movie");
  mtst_init();
  CHECK(moqtrun_test_publish_small_blob(&mtst_hub, 10) != 0);
  u64 cb = mtst_join(SESS_B);
  moqtrun_test_reset();
  mtst_subscribe_p(SESS_B, cb, &f, 2, &p0);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(4) == 0);
}

/* A publisher that leaves and re-PUBLISHes re-attaches its subscribers
 * with the state they SUBSCRIBEd with: FORWARD 0 still holds every Object
 * back (5.1: only the subscriber changes Forward State), and the Request
 * ID and parameters survive. */
static void test_moqtrun_sub_reattach_keeps_state(void) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_ftn    f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  p.items[1].type = MOQCTL_PARAM_SUBSCRIBER_PRIORITY;
  p.items[1].enc  = MOQCTL_PENC_UINT8;
  p.items[1].u8v  = 7;
  p.n             = 2;
  mtst_subscribe_p(SESS_B, cb, &f, 42, &p);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  ca = mtst_join(SESS_A);
  mtst_publish(SESS_A, ca, &f, 1);
  wired_moqtrun_sub* s = mtst_sub(SESS_A, SESS_B);
  CHECK(s != 0);
  CHECK(s && s->forward_off == 1 && s->request_id == 42);
  CHECK(s && s->has_priority == 1 && s->priority == 7);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 0);
}

/* ===================== Largest Object (10.2.16) ===================== */

/* Header (Type 0x30, alias 1, Group g, Subgroup 0) + n Objects, each ID
 * Delta 0 (IDs first_id.., 11.4.2 chaining) with a 1-byte payload. */
static usz mtst_stream(u64 g, usz n, int hdr, u8* buf) {
  moqdata_subhdr h   = {0};
  usz            off = 0;
  h.type             = 0x30;
  h.track_alias      = 1;
  h.group_id         = g;
  if (hdr)
    moqdata_subhdr_put(wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, &h);
  for (usz i = 0; i < n; i++) {
    u8 b = (u8)i;
    moqdata_obj_put(
        wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, 0,
        wired_span_of(&b, 1));
  }
  return off;
}

/* SUBSCRIBE_OK carries no LARGEST_OBJECT while nothing is published, and
 * the Largest Location once Objects were (MUST, 10.2.16) -- tracked
 * across a keep-open stream's header-less later deliveries. */
static void test_moqtrun_sub_ok_largest(void) {
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subscribe(SESS_B, cb, &f);
  CHECK(mtst_largest() == 0);
  usz n = mtst_stream(4, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 1001, wired_span_of(buf, n), 0);
  n = mtst_stream(4, 2, 0, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 1001, wired_span_of(buf, n), 0);
  mtst_subscribe(SESS_B, cb, &f);
  const moqctl_param* l = mtst_largest();
  CHECK(l != 0);
  CHECK(l && l->loc.group == 4 && l->loc.object == 2);
}

/* Largest-relative filters resolve against the Largest at SUBSCRIBE time
 * (9.3.1): Largest Object -> {G, O+1}, Next Group Start -> {G+1, 0}. */
static void test_moqtrun_sub_filter_from_largest(void) {
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_params lo = mtst_params_filter(MOQCTL_FILTER_LARGEST);
  moqctl_params ng = mtst_params_filter(MOQCTL_FILTER_NEXT_GROUP);
  moqctl_ftn    f  = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  u64 cc = mtst_join(SESS_C);
  mtst_publish(SESS_A, ca, &f, 1);
  usz n = mtst_stream(6, 3, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 1001, wired_span_of(buf, n), 1);
  mtst_subscribe_p(SESS_B, cb, &f, 2, &lo);
  mtst_subscribe_p(SESS_C, cc, &f, 2, &ng);
  wired_moqtrun_sub* b = mtst_sub(SESS_A, SESS_B);
  wired_moqtrun_sub* c = mtst_sub(SESS_A, SESS_C);
  CHECK(b && b->start.group == 6 && b->start.object == 3);
  CHECK(c && c->start.group == 7 && c->start.object == 0);
  CHECK(b && b->has_end_group == 0);
}

/* A datagram's Location counts toward the Largest too. */
static void test_moqtrun_sub_largest_from_datagram(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  mtst_subscribe(SESS_B, cb, &f);
  const moqctl_param* l = mtst_largest();
  CHECK(l && l->loc.group == 0 && l->loc.object == 5);
}

/* A new PUBLISH starts a new Largest: Objects of the previous incarnation
 * no longer count, and the PUBLISH's own LARGEST_OBJECT seeds it. */
static void test_moqtrun_sub_republish_resets_largest(void) {
  moqctl_params lp = {0};
  moqctl_ftn    f  = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  moqtrun_test_relay_alice_chat(&mtst_hub);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subscribe(SESS_B, cb, &f);
  CHECK(mtst_largest() == 0);
  lp.items[0].type       = MOQCTL_PARAM_LARGEST_OBJECT;
  lp.items[0].enc        = MOQCTL_PENC_LOCATION;
  lp.items[0].loc.group  = 7;
  lp.items[0].loc.object = 1;
  lp.n                   = 1;
  mtst_publish_p(SESS_A, ca, &f, 1, &lp);
  mtst_subscribe(SESS_B, cb, &f);
  const moqctl_param* l = mtst_largest();
  CHECK(l && l->loc.group == 7 && l->loc.object == 1);
}

/* The hub's own tracks: a blob's last Object, a live track's current
 * Group (Object 0). */
static void test_moqtrun_sub_largest_own_tracks(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "movie");
  mtst_init();
  CHECK(moqtrun_test_publish_small_blob(&mtst_hub, 10) != 0);
  u64 cb = mtst_join(SESS_B);
  mtst_subscribe(SESS_B, cb, &f);
  const moqctl_param* l = mtst_largest();
  CHECK(l && l->loc.group == 0 && l->loc.object == 0);
  mtst_init();
  moqtrun_test_publish_live(&mtst_hub);
  wired_moqt_tick(&mtst_hub, 1000 + 2 * 2000);
  cb = mtst_join(SESS_B);
  mtst_subscribe(SESS_B, cb, &f);
  l = mtst_largest();
  CHECK(l && l->loc.group == 2 && l->loc.object == 0);
}

void test_moqtrun_sub(void) {
  test_moqtrun_sub_ns_must_match();
  test_moqtrun_sub_ns_max_fields();
  test_moqtrun_sub_same_name_other_ns_coexist();
  test_moqtrun_sub_ns_over_cap_refused();
  test_moqtrun_sub_params_recorded();
  test_moqtrun_sub_params_absent();
  test_moqtrun_sub_forward0_gets_nothing();
  test_moqtrun_sub_forward0_blob_not_sent();
  test_moqtrun_sub_reattach_keeps_state();
  test_moqtrun_sub_ok_largest();
  test_moqtrun_sub_filter_from_largest();
  test_moqtrun_sub_largest_from_datagram();
  test_moqtrun_sub_republish_resets_largest();
  test_moqtrun_sub_largest_own_tracks();
}
