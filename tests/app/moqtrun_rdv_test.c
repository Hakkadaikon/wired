/* Rendezvous: a SUBSCRIBE carrying RENDEZVOUS_TIMEOUT for a track nobody
 * publishes yet is held until a PUBLISH claims it or the timeout expires
 * (draft-ietf-moq-transport-18/19 10.2.6, draft-22 9.20.6; relay rules
 * 18/19 9.5, 22 7.6). Scenarios S1-S18 of the Rendezvous design, each a
 * TLA+ invariant (Rendezvous.tla) or a draft MUST. Shares the recording
 * io stubs (moqtrun_test.c) and the request-stream fixtures
 * (moqtrun_sub_test.c, moqtrun_ns_test.c, moqtrun_subtracks_test.c) of
 * the same unity TU. */

#define MRDV_S1 4
#define MRDV_S2 8

static char mrdv_text[256];
static usz  mrdv_at;

static void mrdv_put(const char* z) {
  while (*z && mrdv_at < sizeof mrdv_text - 1) mrdv_text[mrdv_at++] = *z++;
}

static void mrdv_put_hex(u64 v) {
  static const char hex[] = "0123456789abcdef";
  char              tmp[17];
  usz               n = 0;
  do {
    tmp[n++] = hex[v & 0xF];
    v >>= 4;
  } while (v);
  while (n && mrdv_at < sizeof mrdv_text - 1) mrdv_text[mrdv_at++] = tmp[--n];
}

/* "SOK" SUBSCRIBE_OK, "E<code hex>" REQUEST_ERROR, "ROK" REQUEST_OK,
 * "T<type hex>" anything else. */
static void mrdv_put_msg(u64 type, wired_span body) {
  moqctl_request_error e;
  usz                  off = 0;
  if (type == MOQCTL_T_SUBSCRIBE_OK) mrdv_put("SOK");
  if (type == MOQCTL_T_REQUEST_OK) mrdv_put("ROK");
  if (type == MOQCTL_T_REQUEST_ERROR) {
    CHECK(moqctl_request_error_take(body, &off, &e) == MOQCTL_OK);
    mrdv_put("E");
    mrdv_put_hex(e.error_code);
  }
  if (type != MOQCTL_T_SUBSCRIBE_OK && type != MOQCTL_T_REQUEST_OK &&
      type != MOQCTL_T_REQUEST_ERROR) {
    mrdv_put("T");
    mrdv_put_hex(type);
  }
  mrdv_put("|");
}

static void mrdv_put_call(const moqtrun_test_call* c) {
  wired_span all = wired_span_of(c->payload, c->payload_len);
  usz        off = 0;
  u64        type;
  wired_span body;
  if (c->kind == 6) mrdv_put("FIN|");
  if (c->kind == 7) {
    mrdv_put("RST");
    mrdv_put_hex((u64)c->fin);
    mrdv_put("|");
  }
  if ((c->kind != 3 && c->kind != 12) || c->refused) return;
  while (off < all.n) {
    CHECK(moqctl_peek_type(all, &off, &type, &body) == MOQCTL_OK);
    mrdv_put_msg(type, body);
  }
}

/* Everything the hub did on s's stream sid, in order: messages sent, its
 * FIN, its resets. */
static const char* mrdv_log(wired_wt_session* s, u64 sid) {
  mrdv_at = 0;
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].s == s && g_calls[i].stream_id == sid)
      mrdv_put_call(&g_calls[i]);
  mrdv_text[mrdv_at] = 0;
  return mrdv_text;
}

static int mrdv_is(wired_wt_session* s, u64 sid, const char* want) {
  const char* got = mrdv_log(s, sid);
  usz         i   = 0;
  while (got[i] && got[i] == want[i]) i++;
  if (got[i] != want[i]) printf("  got \"%s\" want \"%s\"\n", got, want);
  return got[i] == want[i];
}

/* The first message on s's stream sid decoded as REQUEST_ERROR. */
static moqctl_request_error mrdv_err(wired_wt_session* s, u64 sid) {
  moqctl_request_error e = {0};
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0, boff = 0;
    u64                      type;
    wired_span               body;
    if (c->s != s || c->stream_id != sid || (c->kind != 3 && c->kind != 12))
      continue;
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type == MOQCTL_T_REQUEST_ERROR)
      CHECK(moqctl_request_error_take(body, &boff, &e) == MOQCTL_OK);
    return e;
  }
  return e;
}

/* Track Alias of the first SUBSCRIBE_OK on s's stream sid; ~0 if none. */
static u64 mrdv_alias(wired_wt_session* s, u64 sid) {
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0, boff = 0;
    u64                      type;
    wired_span               body;
    moqctl_subscribe_ok      ok;
    if (c->s != s || c->stream_id != sid || (c->kind != 3 && c->kind != 12))
      continue;
    moqctl_peek_type(
        wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type != MOQCTL_T_SUBSCRIBE_OK) continue;
    if (moqctl_subscribe_ok_take(mtst_ver(s), body, &boff, &ok) != MOQCTL_OK)
      return ~(u64)0;
    return ok.track_alias;
  }
  return ~(u64)0;
}

/* Rendezvous slots in use. */
static usz mrdv_used(void) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++)
    n += mtst_hub.rdv[i].in_use != 0;
  return n;
}

/* The track every scenario waits for. */
static moqctl_ftn mrdv_f(void) { return mtst_ftn("chat", "room1", "alice"); }

/* A, B joined at clock 0; nobody publishes yet. */
static void mrdv_init(void) {
  mtst_init();
  mtst_join(SESS_A);
  mtst_join(SESS_B);
  wired_moqt_tick(&mtst_hub, 0);
}

/* s SUBSCRIBEs f on its request stream sid with RENDEZVOUS_TIMEOUT rt. */
static void mrdv_hold_f(
    wired_wt_session* s, u64 sid, const moqctl_ftn* f, u64 rt) {
  moqctl_params p = mtst_params_vi(MOQCTL_PARAM_RENDEZVOUS_TIMEOUT, rt);
  mtst_subscribe_p(s, sid, f, mtst_rid += 2, &p);
}

static void mrdv_hold(wired_wt_session* s, u64 sid, u64 rt) {
  moqctl_ftn f = mrdv_f();
  mrdv_hold_f(s, sid, &f, rt);
}

/* A PUBLISHes the awaited track on its own request stream. */
static void mrdv_publish(void) {
  moqctl_ftn f = mrdv_f();
  mtst_publish(SESS_A, MRDV_S1, &f, 1);
}

/* S1 AtMostOneAnswer: a hold resolved by PUBLISH is answered once --
 * SUBSCRIBE_OK, and its deadline passing later sends nothing more. */
static void test_moqtrun_rdv_s1_one_answer(void) {
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  wired_moqt_tick(&mtst_hub, 100);
  mrdv_publish();
  wired_moqt_tick(&mtst_hub, 600);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
}

/* S2 NoSilentDrop + CorrectCode: the deadline answers REQUEST_ERROR
 * TIMEOUT (0x2), exactly at rt and not before, then the hub FINs. */
static void test_moqtrun_rdv_s2_timeout(void) {
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  wired_moqt_tick(&mtst_hub, 499);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  wired_moqt_tick(&mtst_hub, 500);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E2|FIN|"));
  CHECK(mrdv_used() == 0);
}

/* S3 R8/R9: no RENDEZVOUS_TIMEOUT, or 0, is DOES_NOT_EXIST at once. */
static void test_moqtrun_rdv_s3_zero_is_dne(void) {
  moqctl_ftn f = mrdv_f();
  mrdv_init();
  mtst_subscribe(SESS_B, MRDV_S1, &f);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E10|FIN|"));
  mrdv_hold(SESS_B, MRDV_S2, 0);
  CHECK(mrdv_is(SESS_B, MRDV_S2, "E10|FIN|"));
  CHECK(mrdv_used() == 0);
}

/* S4 ResolveOnPublish: B gets SUBSCRIBE_OK on its own stream and is an
 * active subscriber of A's track; A gets its PUBLISH_OK; the slot frees. */
static void test_moqtrun_rdv_s4_resolve(void) {
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  CHECK(mrdv_used() == 1);
  mrdv_publish();
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  CHECK(mrdv_alias(SESS_B, MRDV_S1) == mtst_sub(SESS_A, SESS_B)->track_alias);
  CHECK(mrdv_log(SESS_A, MRDV_S1)[0] != 0);
  CHECK(mrdv_log(SESS_A, MRDV_S1)[0] != 'E');
  CHECK(mtrq_fin_on(MRDV_S1) == 0);
  CHECK(mrdv_used() == 0);
}

/* S5: two subscribers holding one track both resolve; each is told the
 * alias its own subscription's relayed objects carry (Track Alias is
 * per session, draft-22 3.1.3, so the two may share a number). */
static void test_moqtrun_rdv_s5_two_resolved(void) {
  mrdv_init();
  mtst_join(SESS_C);
  mrdv_hold(SESS_B, MRDV_S1, 500);
  mrdv_hold(SESS_C, MRDV_S1, 500);
  mrdv_publish();
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
  CHECK(mrdv_alias(SESS_B, MRDV_S1) == mtst_sub(SESS_A, SESS_B)->track_alias);
  CHECK(mrdv_alias(SESS_C, MRDV_S1) == mtst_sub(SESS_A, SESS_C)->track_alias);
}

/* S6 ClampOK: a longer request is clamped to WIRED_MOQTRUN_RDV_MAX_MS
 * (R7 MAY use a shorter timeout). */
static void test_moqtrun_rdv_s6_clamp(void) {
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 60000);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS - 1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E2|FIN|"));
}

/* S7 NoSilentDrop (TLA+ MC_bug): a subscriber FIN is no cancellation
 * (draft-19 3.3.2) -- the hub neither FINs nor resets the held stream,
 * and the answer still comes: (a) SUBSCRIBE_OK on PUBLISH, (b) TIMEOUT
 * then the hub's FIN, and the slot frees. */
static void test_moqtrun_rdv_s7_fin_keeps_hold(void) {
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  wired_moqt_on_stream_data(&mtst_hub, SESS_B, MRDV_S1, wired_span_of(0, 0), 1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  mrdv_publish();
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  wired_moqt_on_stream_data(&mtst_hub, SESS_B, MRDV_S1, wired_span_of(0, 0), 1);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  wired_moqt_tick(&mtst_hub, 500);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E2|FIN|"));
  CHECK(mtrq_used() == 0);
}

/* S8 CancelClean: RESET_STREAM / STOP_SENDING cancels the hold -- the
 * hub resets its side CANCELLED, and nothing is ever answered there. */
static void test_moqtrun_rdv_s8_reset_cancels(void) {
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MRDV_S1, 0, 0);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "RST1|"));
  CHECK(mrdv_used() == 0);
  mrdv_publish();
  wired_moqt_tick(&mtst_hub, 1000);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "RST1|"));
}

/* S9 CancelClean (session): a closed session's holds go with it, so a
 * new session reusing the same handle and stream id is not answered for
 * the old one's SUBSCRIBE. */
static void test_moqtrun_rdv_s9_session_close(void) {
  moqctl_ftn g = mtst_ftn("chat", "room1", "bob");
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  CHECK(mrdv_used() == 0);
  mtst_join(SESS_B);
  mrdv_hold_f(SESS_B, MRDV_S1, &g, 500);
  moqtrun_test_reset();
  mrdv_publish();
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  CHECK(mrdv_used() == 1);
}

/* B, already at its share, is refused EXCESSIVE_LOAD with the Retry
 * Interval on stream sid. */
static void mrdv_check_load(wired_wt_session* s, u64 sid) {
  CHECK(mrdv_is(s, sid, "E9|FIN|"));
  CHECK(mrdv_err(s, sid).retry_interval == WIRED_MOQTRUN_RDV_RETRY);
}

/* S10 CapacityRespected: past WIRED_MOQTRUN_RDV_PER_SESSION, or past
 * WIRED_MOQTRUN_MAX_RDV hub-wide, the SUBSCRIBE is refused EXCESSIVE_LOAD
 * at once (10.6), never dropped; earlier holds are unaffected. */
static void test_moqtrun_rdv_s10_capacity(void) {
  const usz per = WIRED_MOQTRUN_RDV_PER_SESSION;
  const usz ns  = WIRED_MOQTRUN_MAX_RDV / WIRED_MOQTRUN_RDV_PER_SESSION;
  mrdv_init();
  for (usz i = 0; i <= per; i++) mrdv_hold(SESS_B, MTRQ_ID(i), 500);
  mrdv_check_load(SESS_B, MTRQ_ID(per));
  CHECK(mrdv_used() == per);
  for (usz i = 0; i < per; i++) CHECK(mrdv_is(SESS_B, MTRQ_ID(i), ""));
  mrdv_init();
  for (usz s = 0; s < ns; s++) {
    wired_wt_session* w = (wired_wt_session*)(usz)(100 + s);
    mtst_join(w);
    for (usz i = 0; i < per; i++) mrdv_hold(w, MTRQ_ID(i), 500);
  }
  CHECK(mrdv_used() == WIRED_MOQTRUN_MAX_RDV);
  mrdv_hold(SESS_B, MRDV_S1, 500);
  mrdv_check_load(SESS_B, MRDV_S1);
  mrdv_publish();
  CHECK(mrdv_is((wired_wt_session*)(usz)100, MTRQ_ID(0), "SOK|"));
  CHECK(mrdv_used() == 0);
}

/* S11: the single-bidi control stream (no request stream to answer on
 * later) is never held: DOES_NOT_EXIST at once. */
static void test_moqtrun_rdv_s11_control_stream(void) {
  u64 cb;
  mrdv_init();
  cb = moqtrun_find_by_wt(&mtst_hub, SESS_B)->control_stream_id;
  mrdv_hold(SESS_B, cb, 500);
  CHECK(mtrq_err_on(cb) == MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mrdv_used() == 0);
}

/* S12 (18/19 9.5, 22 7.6 MUST NOT also forward): C holds the track and
 * has SUBSCRIBE_TRACKS on its namespace -- C gets SUBSCRIBE_OK and no
 * hub-opened PUBLISH; D with SUBSCRIBE_TRACKS only gets the PUBLISH. */
static void test_moqtrun_rdv_s12_subtracks_skips_held(void) {
  moqctl_publish got[2];
  mrdv_init();
  mtst_join(SESS_C);
  mtst_join(SESS_D);
  mtst_subtracks(SESS_C, MRDV_S1, "chat");
  mrdv_hold(SESS_C, MRDV_S2, 500);
  mtst_subtracks(SESS_D, MRDV_S1, "chat");
  mrdv_publish();
  CHECK(mrdv_is(SESS_C, MRDV_S2, "SOK|"));
  CHECK(mtst_pub_opens(SESS_C, got, 2) == 0);
  CHECK(mtst_pub_opens(SESS_D, got, 2) == 1);
}

/* S13 AtMostOneAnswer (draft-19 10.9): a REQUEST_UPDATE on a held stream
 * answers the SUBSCRIBE first (TIMEOUT, R7 shorter timeout), then the
 * update (DOES_NOT_EXIST); a later PUBLISH adds nothing. */
static void test_moqtrun_rdv_s13_update_on_hold(void) {
  u8  upd[16];
  usz n = 0;
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  CHECK(moqvi_put(wired_mspan_of(upd, sizeof upd), &n, mtst_rid));
  upd[n++] = 0x00; /* no parameters */
  mtrq_raw(SESS_B, MRDV_S1, MOQTSTAT_T_REQUEST_UPDATE, upd, n);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E2|E10|FIN|"));
  CHECK(mrdv_used() == 0);
  mrdv_publish();
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E2|E10|FIN|"));
}

/* S14: one session holding one track twice -- draft-18 answers the
 * second DUPLICATE_SUBSCRIPTION (6.3), draft-19/22 re-answer
 * SUBSCRIBE_OK with the same alias (5.1). */
static void test_moqtrun_rdv_s14_twice_one_session(void) {
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  mrdv_hold(SESS_B, MRDV_S2, 500);
  mrdv_publish();
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  if (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_DUP_SUBSCRIPTION) {
    CHECK(mrdv_is(SESS_B, MRDV_S2, "E19|FIN|"));
    return;
  }
  CHECK(mrdv_is(SESS_B, MRDV_S2, "SOK|"));
  CHECK(mrdv_alias(SESS_B, MRDV_S1) == mrdv_alias(SESS_B, MRDV_S2));
}

/* S15: a PUBLISH_NAMESPACE alone resolves nothing yet (the upstream
 * SUBSCRIBE of 9.5 is a later step): the hold still times out. */
static void test_moqtrun_rdv_s15_namespace_only(void) {
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  mtns_pub(SESS_A, MRDV_S1, "chat/room1");
  wired_moqt_tick(&mtst_hub, 500);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E2|FIN|"));
}

/* S16 (10.4/9.2: GOAWAY does not impact subscription state): a hold
 * survives the hub's GOAWAY to its session and resolves on PUBLISH (the
 * publisher is not drained -- a drained one's new PUBLISH may be refused
 * GOING_AWAY); a session the GOAWAY Timeout closes first loses its hold
 * silently. */
static void test_moqtrun_rdv_s16_goaway(void) {
  u64 now = 0;
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  wired_moqt_on_session_draining(&mtst_hub, SESS_B);
  mrdv_publish();
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, WIRED_MOQTRUN_RDV_MAX_MS);
  wired_moqt_goaway(&mtst_hub, wired_span_of(0, 0), 100);
  while (!moqtrun_find_by_wt(&mtst_hub, SESS_B)->closing &&
         now < WIRED_MOQTRUN_RDV_MAX_MS)
    wired_moqt_tick(&mtst_hub, now += 50);
  CHECK(now < WIRED_MOQTRUN_RDV_MAX_MS);
  wired_moqt_tick(&mtst_hub, now += 50);
  CHECK(mrdv_used() == 0);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
}

/* S17: an unauthorized SUBSCRIBE is refused at once, never held. */
static void test_moqtrun_rdv_s17_unauthorized(void) {
  int calls = 0;
  mrdv_init();
  mtst_hub.authorize_subscribe = mtauth_authorize;
  mtst_hub.authorize_ctx       = &calls;
  mtauth_allow                 = 0;
  mrdv_hold(SESS_B, MRDV_S1, 500);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E1|FIN|"));
  CHECK(mrdv_used() == 0);
}

/* S18 AtMostOneAnswer (22 7.6 order): resolved in the PUBLISH dispatch,
 * so the same tick reaching the deadline finds no hold to expire. */
static void test_moqtrun_rdv_s18_publish_then_deadline(void) {
  mrdv_init();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  wired_moqt_tick(&mtst_hub, 499);
  mrdv_publish();
  wired_moqt_tick(&mtst_hub, 500);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
}

/* Every scenario under every supported draft (S14 the version table). */
static void mtall_rdv(void) {
  test_moqtrun_rdv_s1_one_answer();
  test_moqtrun_rdv_s2_timeout();
  test_moqtrun_rdv_s3_zero_is_dne();
  test_moqtrun_rdv_s4_resolve();
  test_moqtrun_rdv_s5_two_resolved();
  test_moqtrun_rdv_s6_clamp();
  test_moqtrun_rdv_s7_fin_keeps_hold();
  test_moqtrun_rdv_s8_reset_cancels();
  test_moqtrun_rdv_s9_session_close();
  test_moqtrun_rdv_s10_capacity();
  test_moqtrun_rdv_s11_control_stream();
  test_moqtrun_rdv_s12_subtracks_skips_held();
  test_moqtrun_rdv_s13_update_on_hold();
  test_moqtrun_rdv_s14_twice_one_session();
  test_moqtrun_rdv_s15_namespace_only();
  test_moqtrun_rdv_s16_goaway();
  test_moqtrun_rdv_s17_unauthorized();
  test_moqtrun_rdv_s18_publish_then_deadline();
}

void test_moqtrun_rdv(void) { moqtrun_test_allver(mtall_rdv); }
