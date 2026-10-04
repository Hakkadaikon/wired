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
  if (moqctl_subscribe_ok_take(MOQVER_D19, body, &boff, &ok) != MOQCTL_OK)
    return 0;
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

/* A late live subscriber's Location Filter start gates the attach send
 * (5.1.4): a start behind the live edge is clamped to the current Group
 * (no stale replay), a future start holds the attach silent until the
 * clock reaches it -- Groups before the start are never sent. */
static void test_moqtrun_sub_live_attach_filter_start(void) {
  moqctl_params past = mtst_params_filter(MOQCTL_FILTER_ABS_START);
  moqctl_params fut  = mtst_params_filter(MOQCTL_FILTER_ABS_START);
  moqctl_ftn    f    = mtst_ftn("chat", "room1", "movie");
  u8            got[64];
  usz           n;
  fut.items[0].lf.start = moqctl_loc_of(4, 0);
  mtst_init();
  moqtrun_test_publish_live(&mtst_hub);
  wired_moqt_tick(&mtst_hub, 1000 + 2 * 2000); /* Group 2 */
  u64 cb = mtst_join(SESS_B);
  u64 cc = mtst_join(SESS_C);
  moqtrun_test_reset();
  mtst_subscribe_p(SESS_B, cb, &f, 2, &past); /* start {0,0}: behind */
  CHECK(moqtrun_test_count_kind(8) == 1);
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 2);
  mtst_subscribe_p(SESS_C, cc, &f, 2, &fut);       /* start {4,0}: ahead */
  CHECK(moqtrun_test_count_kind(8) == 1);          /* nothing for C yet */
  wired_moqt_tick(&mtst_hub, 1000 + 3 * 2000 + 1); /* Group 3: still held */
  CHECK(moqtrun_test_count_kind(8) == 2);          /* B's Group 3 only */
  CHECK(moqtrun_test_last_kind(8)->s == SESS_B);
  wired_moqt_tick(&mtst_hub, 1000 + 4 * 2000 + 1); /* Group 4: C joins in */
  CHECK(moqtrun_test_count_kind(8) == 4);
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 4);
}

/* ===================== per-request bidi streams ===================== */

/* draft-ietf-moq-transport-19 3.3: a request is the first message of a
 * bidi stream the requester opens; its responses travel on that same
 * stream. Client-initiated bidi stream ids are 0 mod 4 (RFC 9000 2.1). */
#define MTRQ_S1 4
#define MTRQ_S2 8
/* Bidi ids clear of the recorder's control-stream ids (100 up). */
#define MTRQ_ID(i) (1000 + 4 * (u64)(i))

/* TRACK_STATUS body for a track nobody publishes ({x}/y): Request ID 0,
 * no parameters -- a request answered without going live. */
static const u8 MTRQ_TSTAT[] = {0x00, 0x01, 0x01, 0x78, 0x01, 0x79, 0x00};

static u64 mtrq_type_of(const moqtrun_test_call* c) {
  usz        off = 0;
  u64        type;
  wired_span body;
  if (moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
      MOQCTL_OK)
    return 0;
  return type;
}

/* Type of the last message recorded as io kind on stream sid; 0 if none. */
static u64 mtrq_type_on(int kind, u64 sid) {
  for (usz i = g_n_calls; i > 0; i--)
    if (g_calls[i - 1].kind == kind && g_calls[i - 1].stream_id == sid)
      return mtrq_type_of(&g_calls[i - 1]);
  return 0;
}

/* REQUEST_ERROR's error_code from the last stream_send on sid, whichever
 * io kind carried it (control or request stream); ~0 if the last reply
 * there is not a REQUEST_ERROR. */
static u64 mtrq_err_on(u64 sid) {
  for (usz i = g_n_calls; i > 0; i--) {
    if (g_calls[i - 1].kind != 3 && g_calls[i - 1].kind != 12) continue;
    if (g_calls[i - 1].stream_id != sid) continue;
    usz                      off = 0, boff = 0;
    u64                      type;
    wired_span               body;
    moqctl_request_error     e;
    const moqtrun_test_call* c = &g_calls[i - 1];
    if (moqctl_peek_type(
            wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
            MOQCTL_OK ||
        type != MOQCTL_T_REQUEST_ERROR)
      return ~(u64)0;
    if (moqctl_request_error_take(body, &boff, &e) != MOQCTL_OK) return ~(u64)0;
    return e.error_code;
  }
  return ~(u64)0;
}

static usz mtrq_closes(void) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++)
    n += g_calls[i].kind == 11 &&
         g_calls[i].stream_id == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION;
  return n;
}

/* 1 iff the hub FINed its side of sid (io.stream_fin). */
static int mtrq_fin_on(u64 sid) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 6 && g_calls[i].stream_id == sid) return 1;
  return 0;
}

/* Error code of the last io.stream_reset on sid; -1 if none. */
static int mtrq_reset_code(u64 sid) {
  for (usz i = g_n_calls; i > 0; i--)
    if (g_calls[i - 1].kind == 7 && g_calls[i - 1].stream_id == sid)
      return g_calls[i - 1].fin;
  return -1;
}

/* Request-stream slots in use. */
static usz mtrq_used(void) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    n += mtst_hub.reqs[i].in_use != 0;
  return n;
}

/* Sends Type + Length + the given body bytes on sid. */
static void mtrq_raw(
    wired_wt_session* s, u64 sid, u64 type, const u8* body, usz n) {
  u8  buf[MTST_MSG_MAX];
  usz off = 0;
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, type));
  buf[off++] = (u8)(n >> 8);
  buf[off++] = (u8)n;
  bytes_memcpy(buf + off, body, n);
  wired_moqt_on_stream_data(&mtst_hub, s, sid, wired_span_of(buf, off + n), 0);
}

/* SUBSCRIBE f (Request ID rid) encoded into buf; returns its length. */
static usz mtrq_sub_bytes(const moqctl_ftn* f, u64 rid, u8* buf) {
  static moqctl_subscribe m;
  m.request_id = rid;
  m.name       = *f;
  m.params.n   = 0;
  return moqtrun_envelope_put(
      wired_mspan_of(buf, MTST_MSG_MAX), MOQCTL_T_SUBSCRIBE, mtst_enc_subscribe,
      &m);
}

/* A, B joined; A PUBLISHes alice on its control stream. */
static moqctl_ftn mtrq_setup(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  return f;
}

static void test_moqtrun_req_subscribe_answered_on_its_stream(void) {
  moqctl_ftn f  = mtrq_setup();
  u64        cb = moqtrun_find_by_wt(&mtst_hub, SESS_B)->control_stream_id;
  mtst_subscribe(SESS_B, MTRQ_S1, &f);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_last_kind(12) && moqtrun_test_last_kind(12)->s == SESS_B);
  CHECK(mtrq_type_on(3, cb) == 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 1);
}

/* Two requests in flight on two streams, the first split across
 * deliveries around the second: each is reassembled on its own stream and
 * answered there. */
static void test_moqtrun_req_two_streams_answered_apart(void) {
  moqctl_ftn f = mtrq_setup();
  moqctl_ftn g = mtst_ftn("chat", "room1", "bob");
  u8         buf[MTST_MSG_MAX];
  u64        cc = mtst_join(SESS_C);
  mtst_publish(SESS_C, cc, &g, 1);
  usz n = mtrq_sub_bytes(&f, 2, buf);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_B, MTRQ_S1, wired_span_of(buf, 3), 0);
  mtst_subscribe_p(SESS_B, MTRQ_S2, &g, 4, 0);
  CHECK(mtrq_type_on(12, MTRQ_S2) == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(mtrq_type_on(12, MTRQ_S1) == 0);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_B, MTRQ_S1, wired_span_of(buf + 3, n - 3), 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(12) == 2);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0 && mtst_sub(SESS_C, SESS_B) != 0);
}

/* A later reply on an already-answered stream appends to it (draft 10.9:
 * REQUEST_UPDATE is answered on the request's stream). */
static void test_moqtrun_req_update_answered_on_same_stream(void) {
  static const u8 upd[] = {0x02, 0x00}; /* Request ID 2, no parameters */
  moqctl_ftn      f     = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  mtrq_raw(SESS_B, MTRQ_S1, MOQTSTAT_T_REQUEST_UPDATE, upd, sizeof upd);
  CHECK(mtrq_type_on(3, MTRQ_S1) == MOQCTL_T_REQUEST_OK);
  CHECK(moqtrun_test_count_kind(12) == 1);
  CHECK(mtrq_closes() == 0);
}

/* draft 3.3.3: resetting a request stream cancels the request -- the
 * subscription is gone, and a later rejoin of its publisher does not
 * revive it. A reset of a stream carrying no request changes nothing. */
static void test_moqtrun_req_reset_unsubscribes(void) {
  moqctl_ftn f = mtrq_setup();
  mtst_subscribe(SESS_B, MTRQ_S1, &f);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S2, 0, 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  u64 ca = mtst_join(SESS_A);
  mtst_publish(SESS_A, ca, &f, 1);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
}

/* Resetting a PUBLISH's request stream withdraws the track. */
static void test_moqtrun_req_reset_unpublishes(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, MTRQ_S1, &f, 1);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_REQUEST_OK);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  mtst_subscribe(SESS_B, cb, &f);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
}

/* draft 3.3: a bidi stream not starting with a request type closes the
 * session with PROTOCOL_VIOLATION -- a response type, or Object data
 * (whose stream types are unidirectional only). */
static void test_moqtrun_req_bad_first_message_closes(void) {
  static const u8 body[] = {0x00, 0x00};
  mtrq_setup();
  mtrq_raw(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE_OK, body, sizeof body);
  CHECK(mtrq_closes() == 1);
  mtrq_setup();
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_B, MTRQ_S1,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);
  CHECK(mtrq_closes() == 1);
  CHECK(moqtrun_test_count_kind(12) == 0);
}

/* After the first message a request stream carries only what its kind
 * allows (draft 10.4, 10.9, 10.11): a second request, or REQUEST_UPDATE
 * on TRACK_STATUS, is a PROTOCOL_VIOLATION; GOAWAY, and PUBLISH_DONE on a
 * PUBLISH, are not. */
static void test_moqtrun_req_second_message_checked(void) {
  static const u8 upd[]  = {0x00, 0x00};
  static const u8 away[] = {0x00};
  moqctl_ftn      f      = mtrq_setup();
  mtst_subscribe(SESS_B, MTRQ_S1, &f);
  mtrq_raw(SESS_B, MTRQ_S1, MOQCTL_T_GOAWAY, away, sizeof away);
  CHECK(mtrq_closes() == 0);
  mtst_subscribe(SESS_B, MTRQ_S1, &f);
  CHECK(mtrq_closes() == 1);
  mtrq_setup();
  mtrq_raw(
      SESS_B, MTRQ_S1, MOQTSTAT_T_TRACK_STATUS, MTRQ_TSTAT, sizeof MTRQ_TSTAT);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_REQUEST_ERROR);
  mtrq_raw(SESS_B, MTRQ_S1, MOQTSTAT_T_REQUEST_UPDATE, upd, sizeof upd);
  CHECK(mtrq_closes() == 1);
  mtrq_setup();
  mtst_publish(SESS_B, MTRQ_S1, &f, 1);
  mtrq_raw(SESS_B, MTRQ_S1, MOQCTL_T_PUBLISH_DONE, upd, sizeof upd);
  CHECK(mtrq_closes() == 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_REQUEST_OK);
  CHECK(moqtrun_test_count_kind(3) == 1); /* A's own REQUEST_OK only */
}

/* draft 3.3.2: a FIN is not a cancellation. */
static void test_moqtrun_req_fin_keeps_request(void) {
  moqctl_ftn f = mtrq_setup();
  u8         buf[MTST_MSG_MAX];
  usz        n = mtrq_sub_bytes(&f, 2, buf);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_B, MTRQ_S1, wired_span_of(buf, n), 1);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  CHECK(mtrq_fin_on(MTRQ_S1) == 0); /* Established: our side stays open */
  CHECK(mtrq_used() == 1);
}

/* draft 3.3.2/3.3.3: a request answered without establishing anything
 * (REQUEST_ERROR) is complete -- the hub FINs its side after the answer,
 * and the slot is freed once the peer's side has ended too. */
static void test_moqtrun_req_refusal_fins_and_frees(void) {
  moqctl_ftn g = mtst_ftn("chat", "room1", "nobody");
  u8         buf[MTST_MSG_MAX];
  mtrq_setup();
  mtrq_raw(
      SESS_B, MTRQ_S1, MOQTSTAT_T_TRACK_STATUS, MTRQ_TSTAT, sizeof MTRQ_TSTAT);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_REQUEST_ERROR);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
  CHECK(mtrq_used() == 1);
  wired_moqt_on_stream_data(&mtst_hub, SESS_B, MTRQ_S1, wired_span_of(0, 0), 1);
  CHECK(mtrq_used() == 0);
  usz n = mtrq_sub_bytes(&g, 2, buf);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_B, MTRQ_S2, wired_span_of(buf, n), 1);
  CHECK(mtrq_type_on(12, MTRQ_S2) == MOQCTL_T_REQUEST_ERROR);
  CHECK(mtrq_fin_on(MTRQ_S2) == 1);
  CHECK(mtrq_used() == 0);
}

/* Finished requests return their slots: one session can make many more
 * requests than it may hold open at once. */
static void test_moqtrun_req_finished_do_not_exhaust(void) {
  mtst_init();
  mtst_join(SESS_B);
  for (usz i = 0; i < 2 * WIRED_MOQTRUN_MAX_REQS_PER_SESSION; i++) {
    mtrq_raw(
        SESS_B, MTRQ_ID(i), MOQTSTAT_T_TRACK_STATUS, MTRQ_TSTAT,
        sizeof MTRQ_TSTAT);
    wired_moqt_on_stream_data(
        &mtst_hub, SESS_B, MTRQ_ID(i), wired_span_of(0, 0), 1);
  }
  CHECK(moqtrun_test_count_kind(12) == 2 * WIRED_MOQTRUN_MAX_REQS_PER_SESSION);
  CHECK(mtrq_used() == 0);
}

/* One session holds at most WIRED_MOQTRUN_MAX_REQS_PER_SESSION request
 * streams; past it a new one is reset with EXCESSIVE_LOAD (draft 3.3.4)
 * while other sessions are still served, and a closed session's streams
 * return to the pool. */
static void test_moqtrun_req_per_session_cap(void) {
  const u64 over = MTRQ_ID(WIRED_MOQTRUN_MAX_REQS_PER_SESSION);
  mtst_init();
  mtst_join(SESS_B);
  mtst_join(SESS_C);
  for (usz i = 0; i <= WIRED_MOQTRUN_MAX_REQS_PER_SESSION; i++)
    mtrq_raw(
        SESS_B, MTRQ_ID(i), MOQTSTAT_T_TRACK_STATUS, MTRQ_TSTAT,
        sizeof MTRQ_TSTAT);
  CHECK(moqtrun_test_count_kind(12) == WIRED_MOQTRUN_MAX_REQS_PER_SESSION);
  CHECK(mtrq_reset_code(over) == 0x9);
  CHECK(mtrq_closes() == 0);
  mtrq_raw(
      SESS_C, MTRQ_S1, MOQTSTAT_T_TRACK_STATUS, MTRQ_TSTAT, sizeof MTRQ_TSTAT);
  CHECK(moqtrun_test_last_kind(12)->s == SESS_C);
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  CHECK(mtrq_used() == 1);
}

/* With the pool full a peer-opened bidi stream is reset with
 * EXCESSIVE_LOAD, never read as Object data (draft 3.3: Objects travel on
 * unidirectional streams only). */
static void test_moqtrun_req_pool_full_resets(void) {
  wired_wt_session* const sess[] = {SESS_A, SESS_B, SESS_C, SESS_D};
  wired_wt_session* const late   = (wired_wt_session*)(usz)5;
  const usz               per    = WIRED_MOQTRUN_MAX_REQS_PER_SESSION;
  mtst_init();
  for (usz s = 0; s < 4; s++) {
    mtst_join(sess[s]);
    for (usz i = 0; i < per; i++)
      mtrq_raw(
          sess[s], MTRQ_ID(i), MOQTSTAT_T_TRACK_STATUS, MTRQ_TSTAT,
          sizeof MTRQ_TSTAT);
  }
  CHECK(4 * per == WIRED_MOQTRUN_MAX_REQS);
  CHECK(mtrq_used() == WIRED_MOQTRUN_MAX_REQS);
  mtst_join(late);
  wired_moqt_on_stream_data(
      &mtst_hub, late, MTRQ_S1,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);
  CHECK(moqtrun_test_last_kind(7) && moqtrun_test_last_kind(7)->s == late);
  CHECK(mtrq_reset_code(MTRQ_S1) == 0x9);
  CHECK(mtrq_closes() == 0);
}

/* draft-18 10.4: once the hub sends GOAWAY, every new request with a
 * Request ID at or past the watermark it carried (the peer's own next
 * Request ID at that moment) is refused GOING_AWAY; one already pending
 * is unaffected. draft-19/22 have no watermark field, so refusal there
 * is version-generic (moqtrun_is_late) and covered by
 * test_moqtrun_req_second_goaway_closes et al. */
static void test_moqtrun_req_goaway_watermark_d18(void) {
  moqctl_ftn f                               = mtrq_setup();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D18;
  mtst_subscribe(SESS_B, MTRQ_S1, &f); /* rid N: before GOAWAY, OK */
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  wired_moqt_goaway(&mtst_hub, wired_span_of(0, 0), 0); /* watermark = N+2 */
  mtst_subscribe(SESS_B, MTRQ_S2, &f); /* rid N+2: at the watermark */
  CHECK(mtrq_err_on(MTRQ_S2) == MOQCTL_ERR_GOING_AWAY);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0); /* the earlier subscription lives */
}

/* draft 10.4: a second GOAWAY on one request stream is a
 * PROTOCOL_VIOLATION. */
static void test_moqtrun_req_second_goaway_closes(void) {
  static const u8 away[] = {0x00};
  moqctl_ftn      f      = mtrq_setup();
  mtst_subscribe(SESS_B, MTRQ_S1, &f);
  mtrq_raw(SESS_B, MTRQ_S1, MOQCTL_T_GOAWAY, away, sizeof away);
  CHECK(mtrq_closes() == 0);
  mtrq_raw(SESS_B, MTRQ_S1, MOQCTL_T_GOAWAY, away, sizeof away);
  CHECK(mtrq_closes() == 1);
}

/* A reset before the hub answered still resets the hub's side with
 * CANCELLED (draft 3.3.3/3.3.4) and frees the slot. */
static void test_moqtrun_req_reset_unanswered(void) {
  moqctl_ftn f = mtrq_setup();
  u8         buf[MTST_MSG_MAX];
  mtrq_sub_bytes(&f, 2, buf);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_B, MTRQ_S1, wired_span_of(buf, 3), 0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0);
  CHECK(mtrq_reset_code(MTRQ_S1) == 0x1);
  CHECK(mtrq_used() == 0);
}

/* An io table without stream_reply_open cannot answer on a request
 * stream: a peer bidi stream is left to the data path, as before. */
static void test_moqtrun_req_needs_reply_op(void) {
  moqctl_ftn    f      = mtst_ftn("chat", "room1", "alice");
  wired_moqt_io io     = moqtrun_test_io();
  io.stream_reply_open = 0;
  moqtrun_test_reset();
  wired_moqt_init(&mtst_hub, io);
  mtst_join(SESS_B);
  mtst_subscribe(SESS_B, MTRQ_S1, &f);
  CHECK(g_n_calls == 1); /* SETUP only */
}

/* ===================== per-draft parameter scopes ===================== */

/* Control-stream replies (io kind 3) the hub sent to s. */
static usz mtver_replies(wired_wt_session* s) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++)
    n += g_calls[i].kind == 3 && g_calls[i].s == s;
  return n;
}

/* A (draft ver) PUBLISHes alice with params; 1 iff the hub answered. */
static int mtver_publish_answered(int ver, const moqctl_params* params) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca                                     = mtst_join(SESS_A);
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = ver;
  mtst_publish_p(SESS_A, ca, &f, 1, params);
  return mtver_replies(SESS_A) == 1;
}

/* B (draft ver) SUBSCRIBEs to A's alice with params; 1 iff answered. */
static int mtver_subscribe_answered(int ver, const moqctl_params* params) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = ver;
  mtst_subscribe_p(SESS_B, cb, &f, 2, params);
  return mtver_replies(SESS_B) == 1;
}

static moqctl_params mtver_params_vi(u64 type, u64 v) {
  moqctl_params p = {0};
  p.items[0].type = type;
  p.items[0].enc  = MOQCTL_PENC_VARINT;
  p.items[0].vi   = v;
  p.n             = 1;
  return p;
}

/* draft-22 SS9.20.21: INCLUDE_PROPERTIES is a SUBSCRIBE parameter only
 * in draft-22. */
static void test_moqtrun_sub_params_include_properties_d22(void) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_INCLUDE_PROPERTIES, 1);
  CHECK(mtver_subscribe_answered(MOQVER_D22, &p));
  CHECK(!mtver_subscribe_answered(MOQVER_D19, &p));
}

/* draft-22 SS9.20.4 moved OBJECT_DELIVERY_TIMEOUT into PUBLISH. */
static void test_moqtrun_pub_params_delivery_timeout_d22(void) {
  moqctl_params p = mtver_params_vi(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, 100);
  CHECK(mtver_publish_answered(MOQVER_D22, &p));
  CHECK(!mtver_publish_answered(MOQVER_D19, &p));
}

/* draft-18 PUBLISH takes GROUP_ORDER (a SUBSCRIBE_TRACKS-generated
 * PUBLISH echoes it); draft-19 SS10.2.8 does not list PUBLISH. */
static void test_moqtrun_pub_params_group_order_d18(void) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_GROUP_ORDER, 1);
  CHECK(mtver_publish_answered(MOQVER_D18, &p));
  CHECK(!mtver_publish_answered(MOQVER_D19, &p));
}

/* draft-22 9.3: the publisher's initial Subscription parameters ride
 * PUBLISH itself; FORWARD is in PUBLISH's scope on every draft (its
 * draft-19/18 home being PUBLISH too, with PUBLISH_OK on top). */
static void test_moqtrun_pub_params_forward_all_drafts(void) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  CHECK(mtver_publish_answered(MOQVER_D18, &p));
  CHECK(mtver_publish_answered(MOQVER_D19, &p));
  CHECK(mtver_publish_answered(MOQVER_D22, &p));
}

/* draft-18 has no range filters (0x25-0x29): an unknown parameter. */
static void test_moqtrun_sub_params_range_filter_d18(void) {
  static const u8 rng[] = {0x00, 0x03}; /* SetID 0, Start 3 */
  moqctl_params   p     = {0};
  p.items[0].type       = MOQCTL_PARAM_SUBGROUP_FILTER;
  p.items[0].enc        = MOQCTL_PENC_BYTES;
  p.items[0].bytes      = wired_span_of(rng, sizeof rng);
  p.n                   = 1;
  CHECK(!mtver_subscribe_answered(MOQVER_D18, &p));
  CHECK(mtver_subscribe_answered(MOQVER_D19, &p));
}

/* ===================== draft-22 LOCATION_FILTER ===================== */

/* A draft-22 LOCATION_FILTER parameter (SS9.20.9); has 0 is type 0x00. */
static moqctl_params mt22_filter(int has, moqctl_rangeloc rl) {
  moqctl_params p       = {0};
  p.items[0].type       = MOQCTL_PARAM_LOCATION_FILTER;
  p.items[0].enc        = MOQCTL_PENC_RANGELOC22;
  p.items[0].has_filter = has;
  p.items[0].rl         = rl;
  p.n                   = 1;
  return p;
}

static moqctl_rangeloc mt22_rl(
    moqctl_rsk sk, u64 sg, u64 so, moqctl_rek ek, u64 eg, u64 eo) {
  moqctl_rangeloc r = {sk, sg, so, ek, eg, eo};
  return r;
}

/* A publishes alice up to Largest {6,3}; B (draft-22) SUBSCRIBEs with p.
 * B's subscription, 0 when refused. */
static wired_moqtrun_sub* mt22_subscribe(const moqctl_params* p) {
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  usz n = mtst_stream(6, 4, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 1001, wired_span_of(buf, n), 1);
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D22;
  mtst_subscribe_p(SESS_B, cb, &f, 2, p);
  return mtst_sub(SESS_A, SESS_B);
}

static int mt22_start_is(const moqctl_params* p, u64 g, u64 o) {
  wired_moqtrun_sub* s = mt22_subscribe(p);
  return s && s->start.group == g && s->start.object == o;
}

/* Starts (SS9.20.9): 0x00 none is unfiltered from {0,0}; 0x01 Relative
 * Start n is {Largest.G + 1 - n, 0} floored at 0; 0x05 Next Object is
 * {Largest.G, Largest.O + 1}; 0x02 Absolute Start is the given Location.
 * All are open-ended. */
static void test_moqtrun_sub_filter22_starts(void) {
  moqctl_rangeloc z    = {0};
  moqctl_params   none = mt22_filter(0, z);
  moqctl_params   rel0 = mt22_filter(
      1, mt22_rl(MOQCTL_RSK_REL_GROUP, 0, 0, MOQCTL_REK_UNBOUNDED, 0, 0));
  moqctl_params rel1 = mt22_filter(
      1, mt22_rl(MOQCTL_RSK_REL_GROUP, 1, 0, MOQCTL_REK_UNBOUNDED, 0, 0));
  moqctl_params rel9 = mt22_filter(
      1, mt22_rl(MOQCTL_RSK_REL_GROUP, 9, 0, MOQCTL_REK_UNBOUNDED, 0, 0));
  moqctl_params next = mt22_filter(
      1, mt22_rl(MOQCTL_RSK_NEXT_OBJ, 0, 0, MOQCTL_REK_UNBOUNDED, 0, 0));
  moqctl_params abs =
      mt22_filter(1, mt22_rl(MOQCTL_RSK_ABS, 2, 1, MOQCTL_REK_UNBOUNDED, 0, 0));
  CHECK(mt22_start_is(&none, 0, 0));
  CHECK(mt22_start_is(&rel0, 7, 0));
  CHECK(mt22_start_is(&rel1, 6, 0));
  CHECK(mt22_start_is(&rel9, 0, 0));
  CHECK(mt22_start_is(&next, 6, 4));
  CHECK(mt22_start_is(&abs, 2, 1));
  CHECK(mt22_subscribe(&abs)->has_end_group == 0);
}

/* Ends (SS9.20.9): 0x03 ends at the last Object of a Group, 0x04 at an
 * explicit Object, both inclusive. */
static void test_moqtrun_sub_filter22_ends(void) {
  moqctl_params grp =
      mt22_filter(1, mt22_rl(MOQCTL_RSK_ABS, 2, 1, MOQCTL_REK_GROUP, 4, 0));
  moqctl_params obj =
      mt22_filter(1, mt22_rl(MOQCTL_RSK_ABS, 2, 1, MOQCTL_REK_OBJ, 4, 5));
  wired_moqtrun_sub* s = mt22_subscribe(&grp);
  CHECK(s && s->has_end_group && s->end_group == 4 && !s->has_end_object);
  s = mt22_subscribe(&obj);
  CHECK(s && s->start.group == 2 && s->start.object == 1);
  CHECK(s && s->has_end_group && s->end_group == 4);
  CHECK(s && s->has_end_object && s->end_object == 5);
}

/* Code of the last REQUEST_ERROR B got on its control stream; ~0 if the
 * last reply is something else. */
static u64 mt22_last_error(void) {
  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0, boff = 0;
  u64                      type;
  wired_span               body;
  moqctl_request_error     e;
  if (!c || c->s != SESS_B) return ~(u64)0;
  if (moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
          MOQCTL_OK ||
      type != MOQCTL_T_REQUEST_ERROR)
    return ~(u64)0;
  if (moqctl_request_error_take(body, &boff, &e) != MOQCTL_OK) return ~(u64)0;
  return e.error_code;
}

/* 0x04 with End Group Delta 0 and End Object before Start Object can
 * never be satisfied: REQUEST_ERROR INVALID_RANGE, no subscription. */
static void test_moqtrun_sub_filter22_inverted(void) {
  moqctl_params inv =
      mt22_filter(1, mt22_rl(MOQCTL_RSK_ABS, 3, 5, MOQCTL_REK_OBJ, 3, 2));
  CHECK(mt22_subscribe(&inv) == 0);
  CHECK(mt22_last_error() == MOQCTL_ERR_INVALID_RANGE);
}

/* The end only gates delivery (SS3.3.1: a subscription does not end at
 * its filter's end): a Group past the end Group, and a datagram past the
 * End Object, are not sent, and the subscription stays. */
static void test_moqtrun_sub_filter22_end_gates(void) {
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_params obj =
      mt22_filter(1, mt22_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_OBJ, 6, 2));
  moqctl_params dg4 =
      mt22_filter(1, mt22_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_OBJ, 0, 4));
  moqctl_params dg5 =
      mt22_filter(1, mt22_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_OBJ, 0, 5));
  wired_moqtrun_sub* s = mt22_subscribe(&obj);
  moqtrun_test_reset();
  usz n = mtst_stream(7, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 1005, wired_span_of(buf, n), 1);
  CHECK(moqtrun_test_count_kind(4) + moqtrun_test_count_kind(5) == 0);
  CHECK(s && s->active);
  n = mtst_stream(6, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 1009, wired_span_of(buf, n), 1);
  CHECK(moqtrun_test_count_kind(4) + moqtrun_test_count_kind(5) == 1);
  mt22_subscribe(&dg4);
  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  CHECK(moqtrun_test_count_kind(9) == 0);
  mt22_subscribe(&dg5);
  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  CHECK(moqtrun_test_count_kind(9) == 1);
}

/* ===================== reserved namespaces ===================== */

/* draft-19 2.4.2/2.4.3: a Track Namespace whose first field is exactly
 * "." MUST be rejected DOES_NOT_EXIST; one whose first field is
 * ".session" names a session-level track, all of which are unrecognized
 * by this hub, so DOES_NOT_EXIST too -- on PUBLISH and SUBSCRIBE alike. */
static void test_moqtrun_reserved_ns_rejected(void) {
  mtst_init();
  u64        ca   = mtst_join(SESS_A);
  u64        cb   = mtst_join(SESS_B);
  moqctl_ftn dot  = mtst_ftn(".", "room1", "alice");
  moqctl_ftn sess = mtst_ftn(".session", "x", "alice");
  mtst_publish(SESS_A, ca, &dot, 1);
  CHECK(mtrq_err_on(ca) == MOQCTL_ERR_DOES_NOT_EXIST);
  mtst_publish(SESS_A, ca, &sess, 1);
  CHECK(mtrq_err_on(ca) == MOQCTL_ERR_DOES_NOT_EXIST);
  mtst_subscribe(SESS_B, cb, &dot);
  CHECK(mtrq_err_on(cb) == MOQCTL_ERR_DOES_NOT_EXIST);
  mtst_subscribe(SESS_B, cb, &sess);
  CHECK(mtrq_err_on(cb) == MOQCTL_ERR_DOES_NOT_EXIST);
}

/* 2.4.2: any OTHER "."-led first field is an unrecognized reserved
 * namespace and MUST pass to the application -- this hub, which serves
 * it like any other namespace. */
static void test_moqtrun_other_dot_ns_served(void) {
  mtst_init();
  u64        ca = mtst_join(SESS_A);
  u64        cb = mtst_join(SESS_B);
  moqctl_ftn f  = mtst_ftn(".x", "room1", "alice");
  mtst_publish(SESS_A, ca, &f, 1);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_OK);
  mtst_subscribe(SESS_B, cb, &f);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
}

/* ============ SUBGROUP_DELIVERY_TIMEOUT (draft-19 8, 10.2.6) ============ */

static moqctl_params mtst_params_vi(u64 type, u64 v) {
  moqctl_params p = {0};
  p.items[0].type = type;
  p.items[0].enc  = MOQCTL_PENC_VARINT;
  p.items[0].vi   = v;
  p.n             = 1;
  return p;
}

/* PUBLISH carrying Track Properties (KVPs to the end of the body). */
static void mtst_publish_props(
    wired_wt_session* s,
    u64               ctrl,
    const moqctl_ftn* f,
    u64               alias,
    wired_span        props) {
  static moqctl_publish m;
  m.request_id       = mtst_rid += 2;
  m.name             = *f;
  m.track_alias      = alias;
  m.params           = (moqctl_params){0};
  m.track_properties = props;
  mtst_send(s, ctrl, MOQCTL_T_PUBLISH, mtst_enc_publish, &m);
}

/* The effective subgroup timeout is min(publisher Track Property,
 * subscriber parameter) when both are non-zero, the non-zero one when
 * only one is set, and 0 (none) otherwise (draft-19 8). */
static void test_moqtrun_sub_subgroup_timeout_min(void) {
  static const u8 props[] = {0x06, 0x03}; /* Property 0x06, varint 3 */
  moqctl_params p5 = mtst_params_vi(MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT, 5);
  moqctl_ftn    f  = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  u64 cc = mtst_join(SESS_C);
  mtst_publish_props(SESS_A, ca, &f, 1, wired_span_of(props, sizeof props));
  mtst_subscribe_p(SESS_B, cb, &f, 2, &p5);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(mtst_sub(SESS_A, SESS_B)->subgroup_timeout == 3); /* min(3, 5) */
  mtst_subscribe(SESS_C, cc, &f);
  CHECK(mtst_sub(SESS_A, SESS_C)->subgroup_timeout == 3); /* publisher's */
  mtst_init();
  ca = mtst_join(SESS_A);
  cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1); /* no Track Properties */
  mtst_subscribe_p(SESS_B, cb, &f, 2, &p5);
  CHECK(mtst_sub(SESS_A, SESS_B)->subgroup_timeout == 5); /* subscriber's */
  mtst_subscribe(SESS_C, mtst_join(SESS_C), &f);
  CHECK(mtst_sub(SESS_A, SESS_C)->subgroup_timeout == 0); /* none */
}

/* REQUEST_UPDATE carrying SUBGROUP_DELIVERY_TIMEOUT re-mins against the
 * publisher's Track Property (draft-19 10.2.6). */
static void test_moqtrun_sub_subgroup_timeout_update(void) {
  static const u8 props[] = {0x06, 0x03};
  static const u8 upd2[]  = {0x02, 0x01, 0x06, 0x02}; /* rid 2: timeout 2 */
  static const u8 upd9[]  = {0x06, 0x01, 0x06, 0x09}; /* rid 6: timeout 9 */
  moqctl_ftn      f       = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish_props(SESS_A, ca, &f, 1, wired_span_of(props, sizeof props));
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  CHECK(mtst_sub(SESS_A, SESS_B)->subgroup_timeout == 3);
  mtrq_raw(SESS_B, MTRQ_S1, MOQTSTAT_T_REQUEST_UPDATE, upd2, sizeof upd2);
  CHECK(mtst_sub(SESS_A, SESS_B)->subgroup_timeout == 2); /* min(3, 2) */
  mtrq_raw(SESS_B, MTRQ_S1, MOQTSTAT_T_REQUEST_UPDATE, upd9, sizeof upd9);
  CHECK(mtst_sub(SESS_A, SESS_B)->subgroup_timeout == 3); /* min(3, 9) */
}

/* The effective subgroup timeout bounds delivery age like the object
 * timeout: a live Group older than it is not sent at attach (draft-19
 * 8: for datagrams and this hub's age model the smaller timeout acts
 * as OBJECT_DELIVERY_TIMEOUT). */
static void test_moqtrun_sub_subgroup_timeout_gates_delivery(void) {
  moqctl_params p = mtst_params_vi(MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT, 400);
  moqctl_ftn    f = mtst_ftn("chat", "room1", "movie");
  mtst_init();
  moqtrun_test_publish_live(&mtst_hub);
  wired_moqt_tick(&mtst_hub, 1000 + 2500); /* Group 1, age 500ms */
  u64 cb = mtst_join(SESS_B);
  moqtrun_test_reset();
  mtst_subscribe_p(SESS_B, cb, &f, 2, &p);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(8) == 0); /* 500 > 400: held */
}

void test_moqtrun_sub(void) {
  test_moqtrun_sub_filter22_starts();
  test_moqtrun_sub_filter22_ends();
  test_moqtrun_sub_filter22_inverted();
  test_moqtrun_sub_filter22_end_gates();
  test_moqtrun_sub_params_include_properties_d22();
  test_moqtrun_pub_params_delivery_timeout_d22();
  test_moqtrun_pub_params_group_order_d18();
  test_moqtrun_pub_params_forward_all_drafts();
  test_moqtrun_sub_params_range_filter_d18();
  test_moqtrun_sub_ns_must_match();
  test_moqtrun_reserved_ns_rejected();
  test_moqtrun_other_dot_ns_served();
  test_moqtrun_sub_subgroup_timeout_min();
  test_moqtrun_sub_subgroup_timeout_update();
  test_moqtrun_sub_subgroup_timeout_gates_delivery();
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
  test_moqtrun_sub_live_attach_filter_start();
  test_moqtrun_req_subscribe_answered_on_its_stream();
  test_moqtrun_req_two_streams_answered_apart();
  test_moqtrun_req_update_answered_on_same_stream();
  test_moqtrun_req_reset_unsubscribes();
  test_moqtrun_req_reset_unpublishes();
  test_moqtrun_req_bad_first_message_closes();
  test_moqtrun_req_second_message_checked();
  test_moqtrun_req_fin_keeps_request();
  test_moqtrun_req_refusal_fins_and_frees();
  test_moqtrun_req_finished_do_not_exhaust();
  test_moqtrun_req_per_session_cap();
  test_moqtrun_req_pool_full_resets();
  test_moqtrun_req_goaway_watermark_d18();
  test_moqtrun_req_second_goaway_closes();
  test_moqtrun_req_reset_unanswered();
  test_moqtrun_req_needs_reply_op();
}
