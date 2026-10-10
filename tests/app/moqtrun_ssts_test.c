/* Hub SSTS (sender-side track switching, moqtail-compatible; draft-22
 * sessions only, opt-in): SETUP option 0x09 SSTS_ALGORITHMS, the
 * SWITCHING_SET_ASSIGNMENT (0x41) membership, and the per-group forward
 * gate -- one member per group, decided at the group's first arrival and
 * final (tasks/loopeng/moqt/TrackSwitch/SstsDecision.tla: DecisionFinal,
 * OneMemberPerGroup, ForwardAfterDecision, WholeGroup). Shares the
 * recording io stubs (moqtrun_test.c) and the subscription fixtures
 * (moqtrun_sub_test.c, moqtrun_upd_test.c) of the same unity TU. */

#define MTSS_SET 7
#define MTSS_HI_KBPS 2000
#define MTSS_LO_KBPS 500
#define MTSS_SID_HI 4 /* B's request stream SUBSCRIBEing screen */
#define MTSS_SID_LO 8 /* B's request stream SUBSCRIBEing screen-lo */
#define MTSS_SETUP_SID 2

static const u64 mtss_algs_both[] = {
    MOQSSTS_ALG_BACKPRESSURE, MOQSSTS_ALG_DEFAULT};

static u64 mtss_ctrl_a, mtss_ctrl_b;
static u64 mtss_ah, mtss_al; /* B's aliases for hi / lo */
static u64 mtss_pub_sid;

static moqctl_ftn mtss_hi(void) { return mtst_ftn("chat", "room1", "screen"); }

static moqctl_ftn mtss_lo(void) {
  return mtst_ftn("chat", "room1", "screen-lo");
}

static int mtss_enc_setup(wired_mspan buf, usz* off, const void* m) {
  return moqctl_setup_encode(buf, off, m);
}

/* Client s's SETUP (uni control stream) advertising algs[0..n); n < 0
 * omits the option. */
static void mtss_client_setup(wired_wt_session* s, const u64* algs, int n) {
  moqctl_setup m = {0};
  u8           buf[64];
  for (int i = 0; i < n; i++) m.ssts_algs[i] = algs[i];
  m.ssts_alg_n = (u8)(n < 0 ? 0 : n);
  m.has_ssts   = (u8)(n >= 0);
  usz len      = moqtrun_envelope_put(
      wired_mspan_of(buf, sizeof buf), MOQCTL_T_SETUP, mtss_enc_setup, &m);
  CHECK(len != 0);
  wired_moqt_on_stream_data(
      &mtst_hub, s, MTSS_SETUP_SID, wired_span_of(buf, len), 0);
}

/* SWITCHING_SET_ASSIGNMENT param. */
static moqctl_params mtss_ssa(u64 set, u64 alg, u64 kbps, u64 activate) {
  moqctl_params p               = {0};
  p.items[0].type               = MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT;
  p.items[0].enc                = MOQCTL_PENC_SSA;
  p.items[0].ssa.set_id         = set;
  p.items[0].ssa.algorithm_id   = alg;
  p.items[0].ssa.threshold_kbps = kbps;
  p.items[0].ssa.weight         = 1;
  p.items[0].ssa.activate       = activate;
  p.n                           = 1;
  return p;
}

/* SUBSCRIBE_OK's alias from the last reply on request stream sid; ~0 if
 * the last reply there is something else. */
static u64 mtss_ok_alias(u64 sid) {
  static moqctl_subscribe_ok ok;
  for (usz i = g_n_calls; i > 0; i--) {
    const moqtrun_test_call* c   = &g_calls[i - 1];
    usz                      off = 0, boff = 0;
    u64                      type;
    wired_span               body;
    if ((c->kind != 12 && c->kind != 3) || c->stream_id != sid) continue;
    if (moqctl_peek_type(
            wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
            MOQCTL_OK ||
        type != MOQCTL_T_SUBSCRIBE_OK)
      return ~(u64)0;
    if (moqctl_subscribe_ok_take(mtst_ver(c->s), body, &boff, &ok) != MOQCTL_OK)
      return ~(u64)0;
    return ok.track_alias;
  }
  return ~(u64)0;
}

/* B SUBSCRIBEs f on request stream sid, carrying params when given. */
static void mtss_sub(u64 sid, moqctl_ftn f, const moqctl_params* params) {
  mtst_subscribe_p(SESS_B, sid, &f, mtst_rid += 2, params);
}

/* Hub runs algs[0..n) (n 0: off); A and B join under draft ver; A
 * PUBLISHes screen (alias 1) and screen-lo (alias 2). */
static void mtss_init_ver(const u64* algs, usz n, int ver) {
  moqctl_ftn hi = mtss_hi(), lo = mtss_lo();
  g_moqtrun_test_ver = ver;
  mtst_init();
  mtst_hub.ssts_algs  = algs;
  mtst_hub.ssts_alg_n = n;
  mtss_ctrl_a         = mtst_join(SESS_A);
  mtss_ctrl_b         = mtst_join(SESS_B);
  mtst_publish(SESS_A, mtss_ctrl_a, &hi, 1);
  mtst_publish(SESS_A, mtss_ctrl_a, &lo, 2);
  mtss_pub_sid = 1002;
}

static void mtss_init(const u64* algs, usz n) {
  mtss_init_ver(algs, n, MOQVER_D22);
}

/* The standard room: hub and B both run backpressure + default; B puts
 * hi and lo into set MTSS_SET (backpressure, activate) on their own
 * request streams. */
static void mtss_room_act(u64 alg, u64 activate) {
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  moqctl_params ph = mtss_ssa(MTSS_SET, alg, MTSS_HI_KBPS, activate);
  moqctl_params pl = mtss_ssa(MTSS_SET, alg, MTSS_LO_KBPS, activate);
  mtss_sub(MTSS_SID_HI, mtss_hi(), &ph);
  mtss_ah = mtss_ok_alias(MTSS_SID_HI);
  mtss_sub(MTSS_SID_LO, mtss_lo(), &pl);
  mtss_al = mtss_ok_alias(MTSS_SID_LO);
  CHECK(mtss_ah != ~(u64)0 && mtss_al != ~(u64)0 && mtss_ah != mtss_al);
}

static void mtss_room(void) { mtss_room_act(MOQSSTS_ALG_BACKPRESSURE, 2); }

/* SUBGROUP_HEADER (0x30, alias a, Group g) when hdr, then n 1-byte
 * Objects (IDs chained from first). */
static usz mtss_wire(u64 a, u64 g, usz n, int hdr, u8* buf) {
  moqdata_subhdr h   = {0};
  usz            off = 0;
  wired_mspan    out = wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD);
  h.type             = 0x30;
  h.track_alias      = a;
  h.group_id         = g;
  if (hdr) moqdata_subhdr_put(out, &off, &h);
  for (usz i = 0; i < n; i++) {
    u8 b = (u8)i;
    moqdata_obj_put(out, &off, 0, wired_span_of(&b, 1));
  }
  return off;
}

/* A opens a publisher stream of track pub_alias, Group g: n Objects,
 * FIN with them when fin. Returns its stream id. */
static u64 mtss_push(u64 pub_alias, u64 g, usz n, int fin) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u64 sid = mtss_pub_sid += 4;
  usz len = mtss_wire(pub_alias, g, n, 1, buf);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, sid, wired_span_of(buf, len), fin);
  return sid;
}

/* n more Objects on A's open stream sid (header-less round). */
static void mtss_more(u64 sid, usz n, int fin) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz len = mtss_wire(0, 0, n, 0, buf);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, sid, wired_span_of(buf, len), fin);
  wired_moqt_tick(&mtst_hub, 0);
}

/* 1 iff call c opened a stream to B whose SUBGROUP_HEADER names alias a
 * and Group g. */
static int mtss_is_open(const moqtrun_test_call* c, u64 a, u64 g) {
  usz        off = 0;
  u64        type, al, gr;
  wired_span p = wired_span_of(c->payload, c->payload_len);
  if (c->s != SESS_B || (c->kind != 4 && c->kind != 5)) return 0;
  if (!moqvi_take(p, &off, &type) || !moqvi_take(p, &off, &al)) return 0;
  return moqvi_take(p, &off, &gr) && al == a && gr == g;
}

/* Streams opened to B for (alias a, Group g). */
static usz mtss_opens(u64 a, u64 g) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) n += (usz)mtss_is_open(&g_calls[i], a, g);
  return n;
}

/* Accepted bytes-carrying sends to B on the stream opened for (a, g)
 * after its open (continuation rounds). */
static usz mtss_sends(u64 a, u64 g) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    if (!mtss_is_open(&g_calls[i], a, g)) continue;
    for (usz j = i + 1; j < g_n_calls; j++)
      n += g_calls[j].kind == 3 && g_calls[j].s == SESS_B &&
           g_calls[j].stream_id == g_calls[i].stream_id;
  }
  return n;
}

/* One group of both variants, one-shot (hi first). */
static void mtss_group_both(u64 g) {
  mtss_push(1, g, 1, 1);
  mtss_push(2, g, 1, 1);
}

/* 1 iff exactly one member forwarded Group g: lo when want_lo. */
static int mtss_got(u64 g, int want_lo) {
  usz l = mtss_opens(mtss_al, g), h = mtss_opens(mtss_ah, g);
  return want_lo ? (l == 1 && h == 0) : (l == 0 && h == 1);
}

static moqtss_sess* mtss_b(void) {
  return &moqtrun_find_by_wt(&mtst_hub, SESS_B)->ssts;
}

/* B's set MTSS_SET, or 0. */
static const moqtss_set* mtss_set7(void) {
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (mtss_b()->sets[k].in_use && mtss_b()->sets[k].set_id == MTSS_SET)
      return &mtss_b()->sets[k];
  return 0;
}

/* ===================== SETUP option 0x09 ===================== */

/* The hub's SETUP on a fresh tok session, decoded into *s; its raw
 * payload in *raw. */
static int mtss_hub_setup(
    const char* tok, const u64* algs, usz n, moqctl_setup* s, wired_span* raw) {
  usz        off = 0, boff = 0;
  u64        type;
  wired_span body;
  mtst_init();
  mtst_hub.ssts_algs  = algs;
  mtst_hub.ssts_alg_n = n;
  wired_moqt_on_session(
      &mtst_hub, SESS_A, wired_span_of(0, 0), moqtrun_test_proto(tok));
  const moqtrun_test_call* c = moqtrun_test_last_kind(5);
  if (!c) return 0;
  *raw = wired_span_of(c->payload, c->payload_len);
  moqctl_peek_type(*raw, &off, &type, &body);
  return moqctl_setup_take(body, &boff, s) == MOQCTL_OK;
}

static int mtss_has_bytes(wired_span hay, const u8* n, usz nn) {
  for (usz i = 0; i + nn <= hay.n; i++)
    if (!ct_diffn(hay.p + i, n, nn)) return 1;
  return 0;
}

/* Configured: the draft-22 SETUP carries 0x09 = Length 4 + varints
 * 0xff01 (MOQT varint, 3 bytes: c0 ff 01) and 0 (00), in configured
 * order; unconfigured, or a draft-19 session, carries no such option. */
static void test_moqtrun_ssts_setup_option(void) {
  static const u8 val[] = {0x04, 0xc0, 0xff, 0x01, 0x00};
  moqctl_setup    s;
  wired_span      raw;
  CHECK(mtss_hub_setup("moqt-22", mtss_algs_both, 2, &s, &raw));
  CHECK(s.has_ssts && s.ssts_alg_n == 2);
  CHECK(s.ssts_algs[0] == 0xff01 && s.ssts_algs[1] == 0);
  CHECK(mtss_has_bytes(raw, val, sizeof val));
  CHECK(mtss_hub_setup("moqt-22", 0, 0, &s, &raw));
  CHECK(!s.has_ssts);
  CHECK(mtss_hub_setup("moqt-19", mtss_algs_both, 2, &s, &raw));
  CHECK(!s.has_ssts);
}

static int mtss_enc_raw(wired_mspan buf, usz* off, const void* m) {
  const wired_span* v = (const wired_span*)m;
  if (buf.n - *off < v->n) return 0;
  bytes_memcpy(buf.p + *off, v->p, v->n);
  *off += v->n;
  return 1;
}

/* A client SETUP whose SSTS_ALGORITHMS value ends mid-varint closes the
 * session KEY_VALUE_FORMATTING_ERROR (draft-22 1.4, 18/19 1.4.3). */
static void test_moqtrun_ssts_setup_malformed_closes(void) {
  static const u8 opt[] = {0x09, 0x02, 0x00, 0x80}; /* 80: 2-byte, cut */
  wired_span      v     = wired_span_of(opt, sizeof opt);
  u8              buf[64];
  mtss_init(mtss_algs_both, 2);
  usz len = moqtrun_envelope_put(
      wired_mspan_of(buf, sizeof buf), MOQCTL_T_SETUP, mtss_enc_raw, &v);
  CHECK(len != 0);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_B, MTSS_SETUP_SID, wired_span_of(buf, len), 0);
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  CHECK(c && c->s == SESS_B && c->stream_id == MOQCTL_CLOSE_KVFMT_ERROR);
}

/* Negotiated = client's list intersected with the hub's; an absent or
 * empty client list, or a hub with SSTS off, negotiates nothing. */
static void test_moqtrun_ssts_negotiation(void) {
  static const u64 bp[]  = {MOQSSTS_ALG_BACKPRESSURE};
  static const u64 def[] = {MOQSSTS_ALG_DEFAULT};
  static const u64 odd[] = {0xff02, MOQSSTS_ALG_DEFAULT};
  mtss_init(bp, 1);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  CHECK(mtss_b()->algs == 2);
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, odd, 2);
  CHECK(mtss_b()->algs == 1);
  mtss_init(bp, 1);
  mtss_client_setup(SESS_B, def, 1);
  CHECK(mtss_b()->algs == 0);
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, 0, -1);
  CHECK(mtss_b()->algs == 0);
  mtss_init(0, 0);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  CHECK(mtss_b()->algs == 0);
}

/* ===================== assignment refusals ===================== */

/* Hub runs SSTS, B negotiated only default: an assignment naming
 * backpressure is REQUEST_ERROR UNSUPPORTED_EXTENSION, the session lives;
 * the same with no client option at all. */
static void test_moqtrun_ssts_refused_not_negotiated(void) {
  static const u64 def[] = {MOQSSTS_ALG_DEFAULT};
  moqctl_params    p     = mtss_ssa(1, MOQSSTS_ALG_BACKPRESSURE, 500, 1);
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, def, 1);
  mtss_sub(MTSS_SID_HI, mtss_hi(), &p);
  CHECK(mtrq_err_on(MTSS_SID_HI) == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  CHECK(mtrq_closes() == 0);
  mtss_init(mtss_algs_both, 2);
  mtss_sub(MTSS_SID_HI, mtss_hi(), &p);
  CHECK(mtrq_err_on(MTSS_SID_HI) == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  CHECK(mtrq_closes() == 0);
}

/* 1 iff the hub closed B with PROTOCOL_VIOLATION. */
static int mtss_b_violated(void) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 11 && g_calls[i].s == SESS_B)
      return g_calls[i].stream_id == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION;
  return 0;
}

/* Hub SSTS off: the parameter stays unknown -- SUBSCRIBE or
 * REQUEST_UPDATE carrying it closes the session PROTOCOL_VIOLATION. */
static void test_moqtrun_ssts_off_violates(void) {
  moqctl_params p = mtss_ssa(1, MOQSSTS_ALG_DEFAULT, 500, 1);
  mtss_init(0, 0);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  mtss_sub(MTSS_SID_HI, mtss_hi(), &p);
  CHECK(mtss_b_violated());
  mtss_init(0, 0);
  mtss_sub(MTSS_SID_HI, mtss_hi(), 0);
  CHECK(mtss_ok_alias(MTSS_SID_HI) != ~(u64)0);
  mtup_update(SESS_B, MTSS_SID_HI, &p);
  CHECK(mtss_b_violated());
}

/* A track already in set 7 re-assigned to set 8 by REQUEST_UPDATE:
 * UNSUPPORTED_EXTENSION; re-tuning inside set 7 is accepted. */
static void test_moqtrun_ssts_track_in_other_set(void) {
  moqctl_params p8 = mtss_ssa(8, MOQSSTS_ALG_BACKPRESSURE, 500, 2);
  moqctl_params p7 = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 3000, 2);
  mtss_room();
  mtup_update(SESS_B, MTSS_SID_LO, &p8);
  CHECK(mtrq_err_on(MTSS_SID_LO) == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  mtup_update(SESS_B, MTSS_SID_HI, &p7);
  CHECK(mtup_reply(MTSS_SID_HI, &(wired_span){0}) == MOQCTL_T_REQUEST_OK);
  CHECK(mtrq_closes() == 0);
}

/* ===================== forward gate (SstsDecision.tla) =====================
 */

/* OneMemberPerGroup + WholeGroup: hi's Group 0 arrives first and decides
 * the group (backpressure starts at the lowest tier: lo); hi is not
 * opened, lo's Group 0 is, under B's own lo alias. */
static void test_moqtrun_ssts_one_member_per_group(void) {
  mtss_room();
  mtss_group_both(0);
  CHECK(mtss_got(0, 1));
}

/* ForwardAfterDecision: the unchosen member's keep-open Group never
 * reaches B, however many rounds it carries; the decision exists for the
 * group before anything is forwarded. */
static void test_moqtrun_ssts_forward_after_decision(void) {
  mtss_room();
  u64 h = mtss_push(1, 0, 1, 0);
  CHECK(mtss_set7() && mtss_set7()->has_largest && mtss_set7()->largest == 0);
  mtss_more(h, 2, 0);
  mtss_more(h, 1, 1);
  CHECK(mtss_opens(mtss_ah, 0) == 0);
  for (usz i = 0; i < g_n_calls; i++)
    CHECK(
        !(g_calls[i].s == SESS_B && g_calls[i].kind >= 3 &&
          g_calls[i].kind <= 5));
}

/* WholeGroup: the chosen member's keep-open Group arrives from Object 0
 * (its header round) through every continuation round and the FIN. */
static void test_moqtrun_ssts_whole_group(void) {
  mtss_room();
  mtss_push(1, 0, 1, 1);
  u64 l = mtss_push(2, 0, 1, 0);
  mtss_more(l, 1, 0);
  mtss_more(l, 1, 1);
  CHECK(mtss_opens(mtss_al, 0) == 1);
  CHECK(mtss_sends(mtss_al, 0) == 2);
}

/* DecisionFinal: after Group 0 was decided (lo), the algorithm's pick
 * flips to hi; hi's Group 0 still opens nothing and lo's Group 0 keeps
 * flowing to its last Object. */
static void test_moqtrun_ssts_decision_final(void) {
  mtss_room();
  u64 l             = mtss_push(2, 0, 1, 0);
  mtss_b()->bp.tier = 1; /* the pick now would be hi */
  u64 h             = mtss_push(1, 0, 1, 0);
  mtss_more(h, 1, 1);
  mtss_more(l, 1, 1);
  CHECK(mtss_opens(mtss_ah, 0) == 0);
  CHECK(mtss_opens(mtss_al, 0) == 1 && mtss_sends(mtss_al, 0) == 1);
}

/* SstsSticky / MemberChange: the flipped pick takes effect at the next
 * group's first arrival, not mid-group. */
static void test_moqtrun_ssts_switches_at_group_boundary(void) {
  mtss_room();
  u64 l             = mtss_push(2, 0, 1, 0);
  mtss_b()->bp.tier = 1;
  mtss_push(1, 0, 1, 1);
  mtss_more(l, 1, 1);
  mtss_group_both(1);
  CHECK(mtss_got(0, 1));
  CHECK(mtss_got(1, 0));
}

/* The same decision on the ring-backed (reliable) relay: one member per
 * group, the unchosen one never late-attached on a later drain. */
static void test_moqtrun_ssts_one_member_reliable(void) {
  mtss_room();
  mtst_hub.reliable_alias_limit = 1000;
  u64 h                         = mtss_push(1, 0, 1, 0);
  u64 l                         = mtss_push(2, 0, 1, 0);
  mtss_more(h, 1, 1);
  mtss_more(l, 1, 1);
  CHECK(mtss_opens(mtss_ah, 0) == 0);
  CHECK(mtss_opens(mtss_al, 0) == 1);
}

/* Backpressure: lowest member first; after 5 clear groups (depth <= 1:
 * one-shot streams leave none open) the tier rises -- groups 0..3 lo,
 * group 4 hi. */
static void test_moqtrun_ssts_bp_upshift(void) {
  mtss_room();
  for (u64 g = 0; g < 5; g++) mtss_group_both(g);
  for (u64 g = 0; g < 4; g++) CHECK(mtss_got(g, 1));
  CHECK(mtss_got(4, 0));
}

/* Backpressure: on hi, B holding 2 open subscriber streams (hi Groups 5
 * and 6 never FIN) makes Group 7 drop to lo. */
static void test_moqtrun_ssts_bp_downshift(void) {
  mtss_room();
  for (u64 g = 0; g < 5; g++) mtss_group_both(g);
  mtss_push(1, 5, 1, 0);
  mtss_push(1, 6, 1, 0);
  CHECK(mtss_opens(mtss_ah, 5) == 1 && mtss_opens(mtss_ah, 6) == 1);
  mtss_group_both(7);
  CHECK(mtss_got(7, 1));
}

/* Inactive set (moqtail switching_set.rs is_active; subscription.rs
 * gate): activate 2 with only hi assigned forwards NOTHING of the set;
 * activate 1 with the one member forwards it. */
static void test_moqtrun_ssts_inactive_set_forwards_nothing(void) {
  moqctl_params p2 = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 500, 2);
  moqctl_params p1 = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 500, 1);
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  mtss_sub(MTSS_SID_HI, mtss_hi(), &p2);
  mtss_ah = mtss_ok_alias(MTSS_SID_HI);
  mtss_push(1, 0, 1, 1);
  CHECK(mtss_opens(mtss_ah, 0) == 0);
  mtup_update(SESS_B, MTSS_SID_HI, &p1);
  mtss_push(1, 1, 1, 1);
  CHECK(mtss_opens(mtss_ah, 1) == 1);
}

/* A cancelled member leaves its set: with lo's request stream reset, the
 * set's only member hi carries the next group (activate 1). */
static void test_moqtrun_ssts_cancel_removes_member(void) {
  mtss_room_act(MOQSSTS_ALG_BACKPRESSURE, 1);
  mtss_group_both(0);
  CHECK(mtss_got(0, 1));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTSS_SID_LO, 0, 0);
  mtss_group_both(1);
  CHECK(mtss_opens(mtss_ah, 1) == 1 && mtss_opens(mtss_al, 1) == 0);
  CHECK(mtss_b()->sets[0].n + mtss_b()->sets[1].n == 1);
}

/* Default algorithm (0): no bandwidth estimate, so the budget is the
 * hub's cap -- uncapped picks the top member, a 1000 kbps cap lo. */
static void test_moqtrun_ssts_default_cap(void) {
  mtss_room_act(MOQSSTS_ALG_DEFAULT, 2);
  mtss_group_both(0);
  CHECK(mtss_got(0, 0));
  mtst_hub.ssts_cap_kbps = 1000;
  mtss_group_both(1);
  CHECK(mtss_got(1, 1));
}

/* A subscription outside every set is untouched by B's sets, and a
 * draft-19 session never negotiates SSTS (its subscriptions all flow). */
static void test_moqtrun_ssts_nonmember_and_d19(void) {
  moqctl_params pl = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 500, 1);
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  mtss_sub(MTSS_SID_HI, mtss_hi(), 0);
  mtss_ah = mtss_ok_alias(MTSS_SID_HI);
  mtss_sub(MTSS_SID_LO, mtss_lo(), &pl);
  mtss_al = mtss_ok_alias(MTSS_SID_LO);
  mtss_group_both(0);
  CHECK(mtss_opens(mtss_ah, 0) == 1 && mtss_opens(mtss_al, 0) == 1);
  mtss_init_ver(mtss_algs_both, 2, MOQVER_D19);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  CHECK(mtss_b()->algs == 0);
  mtss_sub(MTSS_SID_HI, mtss_hi(), 0);
  mtss_ah = mtss_ok_alias(MTSS_SID_HI);
  mtss_sub(MTSS_SID_LO, mtss_lo(), 0);
  mtss_al = mtss_ok_alias(MTSS_SID_LO);
  mtss_group_both(0);
  CHECK(mtss_opens(mtss_ah, 0) == 1 && mtss_opens(mtss_al, 0) == 1);
}

/* OBJECT_DATAGRAM (Type 0x08: alias, Group, Object ID absent? -- the
 * MOQTRUN_TEST_DG_CHAT shape) of track pub_alias, Group g. */
static void mtss_dg(u64 pub_alias, u8 g) {
  u8 dg[] = {0x08, (u8)pub_alias, g, 0x05, 'h', 'i'};
  wired_moqt_on_datagram(&mtst_hub, SESS_A, wired_span_of(dg, sizeof dg));
}

static usz mtss_dg_to_b(u64 a) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++)
    n += g_calls[i].kind == 9 && g_calls[i].s == SESS_B &&
         g_calls[i].payload_len > 1 && g_calls[i].payload[1] == a;
  return n;
}

/* The datagram fan-out takes the same gate: one member per group. */
static void test_moqtrun_ssts_datagram(void) {
  mtss_room();
  mtss_dg(1, 0);
  mtss_dg(2, 0);
  CHECK(mtss_dg_to_b(mtss_ah) == 0);
  CHECK(mtss_dg_to_b(mtss_al) == 1);
}

/* ============ review round 1: per-set rings, restarts, congestion ============
 */

/* Second sharer: A publishes s2 (alias 3) / s2-lo (alias 4); B puts both
 * into set 8 under algorithm alg. Their aliases in *h / *l. */
static void mtss_second_set_alg(u64 alg, u64* h, u64* l) {
  moqctl_ftn    h2 = mtst_ftn("chat", "room1", "s2");
  moqctl_ftn    l2 = mtst_ftn("chat", "room1", "s2-lo");
  moqctl_params ph = mtss_ssa(8, alg, MTSS_HI_KBPS, 2);
  moqctl_params pl = mtss_ssa(8, alg, MTSS_LO_KBPS, 2);
  mtst_publish(SESS_A, mtss_ctrl_a, &h2, 3);
  mtst_publish(SESS_A, mtss_ctrl_a, &l2, 4);
  mtss_sub(12, h2, &ph);
  *h = mtss_ok_alias(12);
  mtss_sub(16, l2, &pl);
  *l = mtss_ok_alias(16);
}

static void mtss_second_set(u64* h, u64* l) {
  mtss_second_set_alg(MOQSSTS_ALG_BACKPRESSURE, h, l);
}

static void mtss_tier(u64 tier) {
  mtss_b()->bp.tier         = tier;
  mtss_b()->bp.clear_streak = 0;
  mtss_b()->bp.in_cooldown  = 0;
}

/* B1 (OneMemberPerGroup across sets): each sharer numbers its own groups;
 * set 7 far ahead (group 100) must not prune or reuse set 8's group 3. */
static void test_moqtrun_ssts_sets_number_groups_independently(void) {
  u64 h, l;
  mtss_room();
  mtss_second_set(&h, &l);
  for (u64 g = 90; g < 100; g++) mtss_group_both(g);
  mtss_tier(1);
  mtss_push(3, 3, 1, 1); /* set 8 group 3: hi */
  mtss_push(1, 100, 1, 1);
  mtss_tier(0);
  mtss_push(4, 3, 1, 1); /* set 8 lo group 3: already decided */
  CHECK(mtss_opens(h, 3) == 1 && mtss_opens(l, 3) == 0);
}

/* B1 late set: set 8 created after set 7 decided group 3 decides its own
 * group 3 once (one member); set 8 is not the session's pacing set
 * (set 7 holds the lowest slot), so backpressure does not observe. */
static void test_moqtrun_ssts_late_set_decides_once(void) {
  u64 h, l;
  mtss_room();
  mtss_group_both(3);
  CHECK(mtss_got(3, 1));
  mtss_second_set(&h, &l);
  u64 streak = mtss_b()->bp.clear_streak;
  mtss_push(3, 3, 1, 1);
  mtss_push(4, 3, 1, 1);
  CHECK(mtss_opens(h, 3) + mtss_opens(l, 3) == 1);
  CHECK(mtss_b()->bp.clear_streak == streak);
}

/* B2: the publisher reconnects and re-PUBLISHes (group numbers restart at
 * 0) and B re-SUBSCRIBEs both into set 7 (PROBE3): the dead members leave
 * and the set starts a fresh decision ring, so group 0 goes to one member
 * only. */
static void test_moqtrun_ssts_restart_numbering(void) {
  moqctl_ftn    hi = mtss_hi(), lo = mtss_lo();
  moqctl_params ph = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 2000, 2);
  moqctl_params pl = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 500, 2);
  mtss_room();
  for (u64 g = 0; g < 10; g++) mtss_group_both(g);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  mtss_ctrl_a = mtst_join(SESS_A);
  mtst_publish(SESS_A, mtss_ctrl_a, &hi, 1);
  mtst_publish(SESS_A, mtss_ctrl_a, &lo, 2);
  mtss_sub(12, hi, &ph);
  mtss_ah = mtss_ok_alias(12);
  mtss_sub(16, lo, &pl);
  mtss_al = mtss_ok_alias(16);
  moqtrun_test_reset();
  mtss_tier(1);
  mtss_push(1, 0, 1, 1);
  mtss_push(1, 1, 1, 1);
  mtss_tier(0);
  mtss_push(2, 0, 1, 1);
  CHECK(mtss_opens(mtss_ah, 0) + mtss_opens(mtss_al, 0) == 1);
  CHECK(mtss_opens(mtss_ah, 1) == 1);
}

/* R2-B1: a control-stream subscription can re-attach silently to a
 * re-PUBLISHed track (restarting its group numbers while its set may have
 * been pruned), so it may not join a switching set: 0x33. */
static void test_moqtrun_ssts_ctrl_subscribe_refused(void) {
  moqctl_params ph = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 2000, 2);
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  mtss_sub(mtss_ctrl_b, mtss_hi(), &ph);
  CHECK(mtrq_err_on(mtss_ctrl_b) == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  CHECK(mtss_set7() == 0);
  CHECK(mtrq_closes() == 0);
}

/* R2-S1 (moqtail record_group_decision): a late group more than KEEP
 * behind is decided once and kept until the next decision prunes it, so
 * its second member arriving right after gets nothing. */
static void test_moqtrun_ssts_late_group_decided_once(void) {
  mtss_room();
  for (u64 g = 0; g < 16; g++)
    if (g != 8) mtss_push(1, g, 1, 1);
  moqtrun_test_reset();
  mtss_tier(1);
  mtss_push(1, 8, 1, 1);
  mtss_tier(0);
  mtss_push(2, 8, 1, 1);
  CHECK(mtss_opens(mtss_ah, 8) == 1 && mtss_opens(mtss_al, 8) == 0);
}

/* R2-S3: backpressure observes once per group -- on the decisions of the
 * session's lowest-slot active backpressure set (set 7); set 8 holds the
 * same tier. Both sets upshift together after set 7's 5th clear group. */
static void test_moqtrun_ssts_bp_observes_once_per_group(void) {
  u64 h, l;
  mtss_room();
  mtss_second_set(&h, &l);
  for (u64 g = 0; g < 5; g++) {
    mtss_group_both(g);
    mtss_push(3, g, 1, 1);
    mtss_push(4, g, 1, 1);
  }
  for (u64 g = 0; g < 4; g++) {
    CHECK(mtss_got(g, 1));
    CHECK(mtss_opens(h, g) == 0 && mtss_opens(l, g) == 1);
  }
  CHECK(mtss_got(4, 0));
  CHECK(mtss_opens(h, 4) == 1 && mtss_opens(l, 4) == 0);
}

/* Mixed algorithms: set 7 runs backpressure (lowest tier: lo), set 8 the
 * default split with a 2000 kbps cap -- set 8 alone affords its 2000 kbps
 * top member; were set 7 counted in the default split, the halves (1000
 * each) would leave set 8 its 500 kbps member. Each set is decided by its
 * own algorithm only. */
static void test_moqtrun_ssts_mixed_algorithms(void) {
  u64 h, l;
  mtss_room();
  mtst_hub.ssts_cap_kbps = MTSS_HI_KBPS;
  mtss_second_set_alg(MOQSSTS_ALG_DEFAULT, &h, &l);
  mtss_group_both(0);
  mtss_push(3, 0, 1, 1);
  mtss_push(4, 0, 1, 1);
  CHECK(mtss_got(0, 1));
  CHECK(mtss_opens(h, 0) == 1 && mtss_opens(l, 0) == 0);
}

/* A full ladder (MOQSSTS_MAX_MEMBERS) refuses a 5th member
 * INTERNAL_ERROR and stays as it was. */
static void test_moqtrun_ssts_full_set_refused(void) {
  moqctl_ftn    h2 = mtst_ftn("chat", "room1", "s2");
  moqctl_ftn    l2 = mtst_ftn("chat", "room1", "s2-lo");
  moqctl_ftn    x  = mtst_ftn("chat", "room1", "x5");
  moqctl_params p  = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 100, 2);
  mtss_room();
  mtst_publish(SESS_A, mtss_ctrl_a, &h2, 3);
  mtst_publish(SESS_A, mtss_ctrl_a, &l2, 4);
  u64 cc = mtst_join(SESS_C);
  mtst_publish(SESS_C, cc, &x, 5);
  mtss_sub(12, h2, &p);
  mtss_sub(16, l2, &p);
  CHECK(mtss_set7() && mtss_set7()->n == MOQSSTS_MAX_MEMBERS);
  mtss_sub(20, x, &p);
  CHECK(mtrq_err_on(20) == MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(mtss_set7()->n == MOQSSTS_MAX_MEMBERS);
}

/* N1: a cancelled member re-subscribed into another set is accepted, and
 * stale sets never exhaust the session's set slots. */
static void test_moqtrun_ssts_resubscribe_other_set(void) {
  mtss_room_act(MOQSSTS_ALG_BACKPRESSURE, 1);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTSS_SID_LO, 0, 0);
  moqctl_params p9 = mtss_ssa(9, MOQSSTS_ALG_BACKPRESSURE, 500, 1);
  mtss_sub(12, mtss_lo(), &p9);
  CHECK(mtss_ok_alias(12) == mtss_al);
  u64 sid = 12;
  for (u64 set = 20; set < 20 + 2 * WIRED_MOQTRUN_SSTS_SETS; set++) {
    moqctl_params p = mtss_ssa(set, MOQSSTS_ALG_BACKPRESSURE, 500, 1);
    wired_moqt_on_stream_reset(&mtst_hub, SESS_B, sid, 0, 0);
    sid += 4;
    mtss_sub(sid, mtss_lo(), &p);
    CHECK(mtss_ok_alias(sid) == mtss_al);
  }
}

/* N2: a congested subscriber on a lossy member: its hi Group 5 stream is
 * shed (8 refused rounds) while Group 6's stays open -- the reset counts
 * as congestion (moqtail StreamTimeout), so Group 7 drops to lo. */
static void test_moqtrun_ssts_shed_downshifts(void) {
  mtss_room();
  for (u64 g = 0; g < 5; g++) mtss_group_both(g);
  CHECK(mtss_got(4, 0));
  u64 h5 = mtss_push(1, 5, 1, 0);
  mtss_push(1, 6, 1, 0);
  g_stream_send_reject_sess = SESS_B;
  for (int r = 0; r < WIRED_MOQTRUN_RESET_AFTER_BUSY; r++) mtss_more(h5, 1, 0);
  g_stream_send_reject_sess = 0;
  CHECK(mtst_hub.stat_relay_reset == 1);
  CHECK(mtss_b()->timeouts == 1);
  mtss_group_both(7);
  CHECK(mtss_got(7, 1));
  CHECK(mtss_b()->timeouts == 0); /* consumed by the decision */
}

/* A set member's shed Group is not re-opened mid-way: Objects after the
 * reset cannot decode without the Group's start, so the rest of Group 5
 * is not sent; Group 6 goes on. */
static void test_moqtrun_ssts_shed_no_reopen(void) {
  mtss_room();
  for (u64 g = 0; g < 5; g++) mtss_group_both(g);
  u64 h5                    = mtss_push(1, 5, 1, 0);
  g_stream_send_reject_sess = SESS_B;
  for (int r = 0; r < WIRED_MOQTRUN_RESET_AFTER_BUSY; r++) mtss_more(h5, 1, 0);
  g_stream_send_reject_sess = 0;
  CHECK(mtst_hub.stat_relay_reset == 1);
  mtss_more(h5, 1, 0);
  CHECK(mtss_opens(mtss_ah, 5) == 1);
}

/* R2-S2: a session without a backpressure set keeps no reset count (no
 * stale evidence for a backpressure set joining later). */
static void test_moqtrun_ssts_shed_needs_bp_set(void) {
  mtss_room_act(MOQSSTS_ALG_DEFAULT, 2);
  u64 h0 = mtss_push(1, 0, 1, 0);
  CHECK(mtss_opens(mtss_ah, 0) == 1);
  g_stream_send_reject_sess = SESS_B;
  for (int r = 0; r < WIRED_MOQTRUN_RESET_AFTER_BUSY; r++) mtss_more(h0, 1, 0);
  g_stream_send_reject_sess = 0;
  CHECK(mtst_hub.stat_relay_reset == 1);
  CHECK(mtss_b()->timeouts == 0);
}

/* N3: a switch party (SWITCH_FROM old or new side) never joins a set; a
 * set member is reported by moqtss_sub_in_set (SWITCH_FROM refuses it). */
static void test_moqtrun_ssts_switch_party_refused(void) {
  moqctl_params p = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 500, 1);
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  mtss_sub(MTSS_SID_HI, mtss_hi(), 0);
  wired_moqtrun_sub* s = mtst_sub(SESS_A, SESS_B);
  CHECK(s && !moqtss_sub_in_set(s));
  s->sw_role = MOQTSW_ROLE_NEW;
  mtup_update(SESS_B, MTSS_SID_HI, &p);
  CHECK(mtrq_err_on(MTSS_SID_HI) == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  mtss_room();
  CHECK(moqtss_sub_in_set(mtst_sub(SESS_A, SESS_B)));
}

/* An assignment on a REQUEST_UPDATE of a plain subscription joins the
 * set once the update is applied (moqtss_on_update after
 * moqtrun_upd_apply). */
static void test_moqtrun_ssts_update_joins(void) {
  moqctl_params p = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 500, 1);
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  mtss_sub(MTSS_SID_HI, mtss_hi(), 0);
  mtup_update(SESS_B, MTSS_SID_HI, &p);
  CHECK(mtup_reply(MTSS_SID_HI, &(wired_span){0}) == MOQCTL_T_REQUEST_OK);
  CHECK(mtss_set7() && mtss_set7()->n == 1);
}

/* Nit: no switching set holds the hub's own tracks (blob) nor a
 * subscription the hub PUBLISHed (SUBSCRIBE_TRACKS): both refused 0x33. */
static void test_moqtrun_ssts_hub_tracks_refused(void) {
  static const u8 blob[] = {'x'};
  u8              wire[64];
  moqctl_params   p = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 500, 1);
  moqctl_ftn      f = mtst_ftn("chat", "room1", "file");
  mtss_init(mtss_algs_both, 2);
  mtss_client_setup(SESS_B, mtss_algs_both, 2);
  CHECK(wired_moqt_publish_blob(
      &mtst_hub, mtst_z("file"), 9, wired_span_of(blob, 1),
      wired_mspan_of(wire, sizeof wire)));
  mtss_sub(MTSS_SID_HI, f, &p);
  CHECK(mtrq_err_on(MTSS_SID_HI) == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  mtst_subtracks(SESS_B, MTRQ_S1 + 4, "chat");
  wired_moqt_tick(&mtst_hub, 0);
  i64 sid = mtst_pub_stream_id(0);
  CHECK(sid >= 0);
  mtst_pub_ok(SESS_B, (u64)sid);
  mtup_update(SESS_B, (u64)sid, &p);
  CHECK(mtrq_err_on((u64)sid) == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
}

/* N4 window: 20 groups on hi (past the 16-group verdict window) all
 * forward -- the window slides up. */
static void test_moqtrun_ssts_window_slides(void) {
  mtss_room();
  mtss_tier(1);
  for (u64 g = 0; g < 20; g++) {
    mtss_tier(1);
    mtss_push(1, g, 1, 1);
    CHECK(mtss_opens(mtss_ah, g) == 1);
  }
}

/* N4 window full: a late stamp below the base that would push the newest
 * verdict out is ignored -- the late group is not forwarded, group 17's
 * verdict stays. */
static void test_moqtrun_ssts_window_keeps_newest(void) {
  mtss_room();
  for (u64 g = 2; g < 18; g++) {
    mtss_tier(1);
    mtss_push(1, g, 1, 1);
  }
  mtss_tier(1);
  mtss_push(1, 1, 1, 1);
  CHECK(mtss_opens(mtss_ah, 1) == 0);
  CHECK(moqtss_sub_pass(mtst_sub(SESS_A, SESS_B), 17));
}

/* N4 lag inside the window: lo lags hi by 3 groups; hi's decisions still
 * stand when lo arrives with the pick flipped (no duplicate group). */
static void test_moqtrun_ssts_lag_inside_window(void) {
  mtss_room();
  mtss_tier(1);
  for (u64 g = 0; g < 5; g++) mtss_push(1, g, 1, 1);
  mtss_tier(0);
  mtss_push(2, 2, 1, 1);
  CHECK(mtss_opens(mtss_ah, 2) == 1 && mtss_opens(mtss_al, 2) == 0);
}

/* N4 lag outside the window (moqtail DECISION_WINDOW): a decision older
 * than the set's largest - 5 is pruned, so lo's group 0 arriving after
 * hi's group 6 is decided afresh (moqtail behaves the same: a member
 * lagging more than 5 groups can repeat a group). */
static void test_moqtrun_ssts_lag_outside_window(void) {
  mtss_room();
  mtss_tier(1);
  for (u64 g = 0; g < 7; g++) mtss_push(1, g, 1, 1);
  mtss_tier(0);
  mtss_push(2, 0, 1, 1);
  CHECK(mtss_opens(mtss_al, 0) == 1);
}

/* ============ review round 3: pacing set edge cases ============ */

/* A non-pacing backpressure set takes the shared tier clamped to its own
 * ladder: set 7 (pacing, 3 rungs: lo 500 / x5 1000 / hi 2000) climbs to
 * tier 2 after 10 clear groups; set 8 (2 rungs) then picks its own top,
 * rung 1 (s2), never a rung past its ladder. */
static void test_moqtrun_ssts_hold_clamps_to_ladder(void) {
  u64           h, l;
  moqctl_ftn    x  = mtst_ftn("chat", "room1", "x5");
  moqctl_params px = mtss_ssa(MTSS_SET, MOQSSTS_ALG_BACKPRESSURE, 1000, 2);
  mtss_room();
  u64 cc = mtst_join(SESS_C);
  mtst_publish(SESS_C, cc, &x, 5);
  mtss_sub(20, x, &px);
  CHECK(mtss_set7() && mtss_set7()->n == 3);
  mtss_second_set(&h, &l);
  for (u64 g = 0; g < 10; g++) mtss_push(1, g, 1, 1);
  CHECK(mtss_b()->bp.tier == 2);
  CHECK(mtss_opens(mtss_ah, 9) == 1);
  mtss_push(3, 0, 1, 1);
  mtss_push(4, 0, 1, 1);
  CHECK(mtss_opens(h, 0) == 1 && mtss_opens(l, 0) == 0);
}

/* An inactive backpressure set (set 7, activate 3 with 2 members) in the
 * lower slot does not pace: set 8 does, so its 5 clear groups upshift it
 * (group 4: s2). */
static void test_moqtrun_ssts_inactive_set_does_not_pace(void) {
  u64 h, l;
  mtss_room_act(MOQSSTS_ALG_BACKPRESSURE, 3);
  mtss_second_set(&h, &l);
  for (u64 g = 0; g < 5; g++) {
    mtss_push(3, g, 1, 1);
    mtss_push(4, g, 1, 1);
  }
  for (u64 g = 0; g < 4; g++) CHECK(mtss_opens(h, g) == 0);
  CHECK(mtss_opens(h, 4) == 1 && mtss_opens(l, 4) == 0);
}

/* KNOWN LIMITATION (pinned, see moqtssts_run.c): a pacing set that stays
 * live but sends no groups (a paused share) freezes the shared tier --
 * set 8's 10 clear groups never upshift it -- and the session's reset
 * count accumulates across set 8's groups until set 7's next decision
 * consumes it in one observation. */
static void test_moqtrun_ssts_known_limit_paused_pacer_freezes_tier(void) {
  u64 h, l;
  mtss_room();
  mtss_second_set(&h, &l);
  for (u64 g = 0; g < 10; g++) {
    mtss_push(3, g, 1, 1);
    mtss_push(4, g, 1, 1);
    CHECK(mtss_opens(h, g) == 0 && mtss_opens(l, g) == 1);
  }
  CHECK(mtss_b()->bp.tier == 0 && mtss_b()->bp.clear_streak == 0);
  u64 s10                   = mtss_push(4, 10, 1, 0);
  g_stream_send_reject_sess = SESS_B;
  for (int r = 0; r < WIRED_MOQTRUN_RESET_AFTER_BUSY; r++) mtss_more(s10, 1, 0);
  g_stream_send_reject_sess = 0;
  CHECK(mtss_b()->timeouts == 1);
  mtss_push(3, 11, 1, 1);
  mtss_push(4, 11, 1, 1);
  CHECK(mtss_b()->timeouts == 1); /* set 8 does not consume it */
  mtss_push(1, 0, 1, 1);
  CHECK(mtss_b()->timeouts == 0); /* set 7's decision does */
}

void test_moqtrun_ssts(void) {
  test_moqtrun_ssts_setup_option();
  test_moqtrun_ssts_setup_malformed_closes();
  test_moqtrun_ssts_negotiation();
  test_moqtrun_ssts_refused_not_negotiated();
  test_moqtrun_ssts_off_violates();
  test_moqtrun_ssts_track_in_other_set();
  test_moqtrun_ssts_one_member_per_group();
  test_moqtrun_ssts_forward_after_decision();
  test_moqtrun_ssts_whole_group();
  test_moqtrun_ssts_decision_final();
  test_moqtrun_ssts_switches_at_group_boundary();
  test_moqtrun_ssts_one_member_reliable();
  test_moqtrun_ssts_bp_upshift();
  test_moqtrun_ssts_bp_downshift();
  test_moqtrun_ssts_inactive_set_forwards_nothing();
  test_moqtrun_ssts_cancel_removes_member();
  test_moqtrun_ssts_default_cap();
  test_moqtrun_ssts_nonmember_and_d19();
  test_moqtrun_ssts_datagram();
  test_moqtrun_ssts_sets_number_groups_independently();
  test_moqtrun_ssts_late_set_decides_once();
  test_moqtrun_ssts_restart_numbering();
  test_moqtrun_ssts_ctrl_subscribe_refused();
  test_moqtrun_ssts_late_group_decided_once();
  test_moqtrun_ssts_bp_observes_once_per_group();
  test_moqtrun_ssts_mixed_algorithms();
  test_moqtrun_ssts_full_set_refused();
  test_moqtrun_ssts_shed_needs_bp_set();
  test_moqtrun_ssts_hold_clamps_to_ladder();
  test_moqtrun_ssts_inactive_set_does_not_pace();
  test_moqtrun_ssts_known_limit_paused_pacer_freezes_tier();
  test_moqtrun_ssts_resubscribe_other_set();
  test_moqtrun_ssts_shed_downshifts();
  test_moqtrun_ssts_shed_no_reopen();
  test_moqtrun_ssts_switch_party_refused();
  test_moqtrun_ssts_update_joins();
  test_moqtrun_ssts_hub_tracks_refused();
  test_moqtrun_ssts_window_slides();
  test_moqtrun_ssts_window_keeps_newest();
  test_moqtrun_ssts_lag_inside_window();
  test_moqtrun_ssts_lag_outside_window();
  g_moqtrun_test_ver = MOQVER_D19;
}
