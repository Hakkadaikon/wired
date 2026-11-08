/* draft-23 7.5 and 9.19.17: the LARGEST_OBJECT a relay puts in its answers
 * to downstream requests. It counts every upstream source (SUBSCRIBE_OK,
 * PUBLISH, REQUEST_UPDATE_OK, PUBLISH_STATE_NOTIFY, Objects), answers only
 * from an unpaused upstream -- a request on a paused PUBLISH waits in a
 * rendezvous slot while the hub unpauses it -- and includes the parameter
 * whenever it has received any Object. Earlier drafts keep answering at
 * once (each scenario names its draft side by MOQVER_CAP_RELAY_LARGEST).
 * Shares the fixtures of moqtrun_sub_test.c, moqtrun_subtracks_test.c,
 * moqtrun_rdv_test.c and moqtrun_upsub_test.c (same unity TU). */

/* ===================== fixtures ===================== */

static moqctl_params mtlg_loc(u64 g, u64 o) {
  moqctl_params p = {0};
  p.items[0].type = MOQCTL_PARAM_LARGEST_OBJECT;
  p.items[0].enc  = MOQCTL_PENC_LOCATION;
  p.items[0].loc  = moqctl_loc_of(g, o);
  p.n             = 1;
  return p;
}

/* 1 iff params carry LARGEST_OBJECT {g, o}. */
static int mtlg_has(const moqctl_params* params, u64 g, u64 o) {
  const moqctl_param* l =
      moqctl_params_find(params, MOQCTL_PARAM_LARGEST_OBJECT);
  return l && l->loc.group == g && l->loc.object == o;
}

/* A publishes chat/room1/alice on its control stream, carrying params (0:
 * none); B sends SUBSCRIBE_TRACKS "chat"; *pub is the hub's PUBLISH to B. */
static void mtlg_subtracks(const moqctl_params* params, moqctl_publish* pub) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish_p(SESS_A, ca, &f, 1, params);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  CHECK(mtst_pub_opens(SESS_B, pub, 1) == 1);
}

static int mtlg_enc_params(wired_mspan buf, usz* off, const void* m) {
  return moqctl_params_put(buf, off, m);
}

/* A, B joined (mrdv_init); A PUBLISHes the awaited track on its request
 * stream MUPS_PUB_SID, paused or not, with LARGEST_OBJECT {g, o}. */
static void mtlg_pub(int paused, u64 g, u64 o) {
  moqctl_ftn    f = mrdv_f();
  moqctl_params p = mtlg_loc(g, o);
  mrdv_init();
  mups_sids();
  p.items[1].type = MOQCTL_PARAM_FORWARD;
  p.items[1].enc  = MOQCTL_PENC_UINT8;
  p.items[1].u8v  = (u8)!paused;
  p.n             = 2;
  mtst_publish_p(SESS_A, MUPS_PUB_SID, &f, MUPS_ALIAS, &p);
}

/* A sends PUBLISH_STATE_NOTIFY {LARGEST_OBJECT {g, o}} on its stream sid. */
static void mtlg_psn(u64 sid, u64 g, u64 o) {
  static moqctl_params p;
  p = mtlg_loc(g, o);
  mtst_send(SESS_A, sid, MOQCTL_T_PUBLISH_STATE_NOTIFY, mtlg_enc_params, &p);
}

/* A answers REQUEST_OK {LARGEST_OBJECT {g, o}} on its stream sid. */
static void mtlg_rok(u64 sid, u64 g, u64 o) {
  static moqctl_request_ok ok;
  ok.params = mtlg_loc(g, o);
  mtst_send(SESS_A, sid, MOQCTL_T_REQUEST_OK, mtsub_encode_request_ok, &ok);
}

/* The last SUBSCRIBE_OK (or, rok, REQUEST_OK) the hub sent on s's stream
 * sid, its parameters into *out; 0 when there is none. */
static int mtlg_answer(
    wired_wt_session* s, u64 sid, int rok, moqctl_params* out) {
  int found = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    wired_span               all = wired_span_of(c->payload, c->payload_len);
    usz                      off = 0;
    u64                      type;
    wired_span               body;
    if (c->s != s || c->stream_id != sid || (c->kind != 3 && c->kind != 12)) {
      continue;
    }
    while (off < all.n && mt_peek_type(all, &off, &type, &body) == MOQCTL_OK) {
      moqctl_subscribe_ok sok;
      moqctl_request_ok   ok;
      usz                 boff = 0;
      if (!rok && type == MOQCTL_T_SUBSCRIBE_OK &&
          moqctl_subscribe_ok_take(mtst_ver(s), body, &boff, &sok) ==
              MOQCTL_OK) {
        *out  = sok.params;
        found = 1;
      }
      if (rok && type == MOQCTL_T_REQUEST_OK &&
          moqctl_request_ok_take(mtst_ver(s), body, &boff, &ok) == MOQCTL_OK) {
        *out  = ok.params;
        found = 1;
      }
    }
  }
  return found;
}

/* B's SUBSCRIBE_OK on sid carries LARGEST_OBJECT {g, o}. */
static int mtlg_sok_is(u64 sid, u64 g, u64 o) {
  moqctl_params p;
  return mtlg_answer(SESS_B, sid, 0, &p) && mtlg_has(&p, g, o);
}

/* A's published track's Largest is {g, o}. */
static int mtlg_top_is(u64 g, u64 o) {
  const wired_moqtrun_track* t =
      &moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0];
  return t->has_largest && t->largest.group == g && t->largest.object == o;
}

/* ============== upstream sources (7.5 item 1) ============== */

/* 7.5: PUBLISH_STATE_NOTIFY's LARGEST_OBJECT on the PUBLISH's stream
 * raises the Largest, and the next answer carries it. */
static void mtlg_psn_d23(void) {
  mtlg_pub(0, 0, 5);
  mtlg_psn(MUPS_PUB_SID, 0, 7);
  CHECK(mtlg_top_is(0, 7));
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mtlg_sok_is(MRDV_S1, 0, 7));
}

/* draft-22 counts no PUBLISH_STATE_NOTIFY. */
static void mtlg_psn_d22(void) {
  mtlg_pub(0, 0, 5);
  mtlg_psn(MUPS_PUB_SID, 0, 7);
  CHECK(mtlg_top_is(0, 5));
}

static void test_moqtrun_d23lg_psn_raises_largest(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_psn_d23);
  moqtrun_test_vers(
      MOQVER_CAP_PUBLISH_STATE_NOTIFY, MOQVER_CAP_RELAY_LARGEST, mtlg_psn_d22);
}

/* The same on the hub's own upstream SUBSCRIBE: its REQUEST_OK and
 * PUBLISH_STATE_NOTIFY count, as the re-answered SUBSCRIBE_OK shows. */
static void mtlg_up_sources_d23(void) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  u64 sid = (u64)mups_up_sid();
  mups_ok(sid);
  mtlg_psn(sid, 1, 4);
  mups_sub(SESS_B, MRDV_S2);
  CHECK(mtlg_sok_is(MRDV_S2, 1, 4));
  mtlg_rok(sid, 2, 0);
  mups_sub(SESS_B, MRDV_S2 + 4);
  CHECK(mtlg_sok_is(MRDV_S2 + 4, 2, 0));
}

static void test_moqtrun_d23lg_psn_value_in_answer(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_up_sources_d23);
}

/* 7.5: REQUEST_UPDATE_OK's LARGEST_OBJECT on the PUBLISH's stream counts. */
static void mtlg_ruok_d23(void) {
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  mtlg_rok(MUPS_PUB_SID, 0, 9);
  CHECK(mtlg_top_is(0, 9));
}

static void mtlg_ruok_d22(void) {
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  mtlg_rok(MUPS_PUB_SID, 0, 9);
  CHECK(mtlg_top_is(0, 5));
}

static void test_moqtrun_d23lg_ruok_largest_used(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_ruok_d23);
  moqtrun_test_vers(0, MOQVER_CAP_RELAY_LARGEST, mtlg_ruok_d22);
}

/* ============ no answer from a paused upstream (7.5, 7.7) ============ */

/* Unpause REQUEST_UPDATEs (FORWARD 1, PAUSED 0 on draft-23) the hub sent
 * on A's PUBLISH stream. */
static usz mtlg_unpauses(void) {
  u64 v = 9;
  usz n = mups_upd_sent(MUPS_PUB_SID, MOQCTL_PARAM_FORWARD, &v);
  CHECK(n == 0 || v == 1);
  return n;
}

/* B's TRACK_STATUS for the awaited track on its stream sid. */
static void mtlg_tstat(u64 sid) {
  moqctl_ftn f = mrdv_f();
  mtup_tstat(SESS_B, sid, &f);
}

/* B's REQUEST_OK (TRACK_STATUS_OK) on sid carries LARGEST_OBJECT {g, o}. */
static int mtlg_rok_is(u64 sid, u64 g, u64 o) {
  moqctl_params p;
  return mtlg_answer(SESS_B, sid, 1, &p) && mtlg_has(&p, g, o);
}

/* 7.5: a SUBSCRIBE on a PUBLISH that arrived paused is not answered from
 * it: the hub unpauses the PUBLISH (7.7) and answers with what the
 * REQUEST_UPDATE_OK carries, once only. */
static void mtlg_paused_pub_d23(void) {
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  CHECK(mtlg_unpauses() == 1);
  mtlg_rok(MUPS_PUB_SID, 0, 9);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mtlg_sok_is(MRDV_S1, 0, 9));
  CHECK(mrdv_used() == 0);
}

/* Before draft-23 SUBSCRIBE_OK goes at once with the PUBLISH's value. */
static void mtlg_paused_pub_d22(void) {
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mtlg_sok_is(MRDV_S1, 0, 5));
}

static void test_moqtrun_d23lg_paused_pub_waits_resume(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_paused_pub_d23);
  moqtrun_test_vers(0, MOQVER_CAP_RELAY_LARGEST, mtlg_paused_pub_d22);
}

/* 7.5: a paused downstream SUBSCRIBE (PAUSED 1) still needs a Largest,
 * so the hub unpauses the upstream for it too. */
static void mtlg_paused_sub(void) {
  moqctl_ftn    f = mrdv_f();
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  mtlg_pub(1, 0, 5);
  mtst_subscribe_p(SESS_B, MRDV_S1, &f, mtst_rid += 4, &p);
}

static void mtlg_paused_sub_d23(void) {
  mtlg_paused_sub();
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  CHECK(mtlg_unpauses() == 1);
  mtlg_rok(MUPS_PUB_SID, 0, 6);
  CHECK(mtlg_sok_is(MRDV_S1, 0, 6));
}

/* Before draft-23 a paused subscriber neither waits nor unpauses. */
static void mtlg_paused_sub_d22(void) {
  mtlg_paused_sub();
  CHECK(mtlg_sok_is(MRDV_S1, 0, 5));
  CHECK(mtlg_unpauses() == 0);
}

static void test_moqtrun_d23lg_paused_sub_resumes_upstream(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_paused_sub_d23);
  moqtrun_test_vers(0, MOQVER_CAP_RELAY_LARGEST, mtlg_paused_sub_d22);
}

/* 7.5: TRACK_STATUS on a paused PUBLISH is answered after the unpause,
 * with the REQUEST_UPDATE_OK's value, not the PUBLISH's. */
static void mtlg_tstat_d23(void) {
  mtlg_pub(1, 0, 5);
  mtlg_tstat(MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  CHECK(mtlg_unpauses() == 1);
  mtlg_rok(MUPS_PUB_SID, 0, 9);
  CHECK(mtlg_rok_is(MRDV_S1, 0, 9));
  CHECK(mrdv_is(SESS_B, MRDV_S1, "ROK|FIN|"));
}

static void mtlg_tstat_d22(void) {
  mtlg_pub(1, 0, 5);
  mtlg_tstat(MRDV_S1);
  CHECK(mtlg_rok_is(MRDV_S1, 0, 5));
}

static void test_moqtrun_d23lg_tstat_paused_fresh(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_tstat_d23);
  moqtrun_test_vers(0, MOQVER_CAP_RELAY_LARGEST, mtlg_tstat_d22);
}

/* A publisher that never answers the unpause holds each waiter in a
 * rendezvous slot (no hub-side timeout): one unpause for all of them,
 * and past the session's share of slots a new SUBSCRIBE or TRACK_STATUS
 * is refused EXCESSIVE_LOAD at once. */
static void mtlg_wait_slots_d23(void) {
  u64 sid = MRDV_S1;
  mtlg_pub(1, 0, 5);
  for (usz i = 0; i < WIRED_MOQTRUN_RDV_PER_SESSION; i++, sid += 4) {
    mups_sub(SESS_B, sid);
  }
  CHECK(mrdv_used() == WIRED_MOQTRUN_RDV_PER_SESSION);
  CHECK(mtlg_unpauses() == 1);
  mups_sub(SESS_B, sid);
  CHECK(mrdv_err(SESS_B, sid).error_code == MOQCTL_ERR_EXCESSIVE_LOAD);
  mtlg_tstat(sid + 4);
  CHECK(mrdv_err(SESS_B, sid + 4).error_code == MOQCTL_ERR_EXCESSIVE_LOAD);
  wired_moqt_tick(&mtst_hub, 1000000);
  CHECK(mrdv_used() == WIRED_MOQTRUN_RDV_PER_SESSION);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
}

static void test_moqtrun_d23lg_wait_slots_bounded(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_wait_slots_d23);
}

/* ===================== the upstream fails (7.5) ===================== */

/* 1 iff the hub sent no REQUEST_ERROR on B's stream sid. */
static int mtlg_no_err(u64 sid) {
  const char* z = mrdv_log(SESS_B, sid);
  while (*z && *z != 'E') {
    z++;
  }
  return *z == 0;
}

static int mtlg_paused(void) {
  return moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].pub_paused;
}

/* A refused unpause fails its waiter with the publisher's code (never
 * SUBSCRIBE_OK from a paused PUBLISH), and the PUBLISH stays paused. */
static void mtlg_resume_refused_d23(void) {
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  mtst_pub_err(SESS_A, MUPS_PUB_SID, MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(mrdv_err(SESS_B, MRDV_S1).error_code == MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E3|FIN|"));
  CHECK(mtlg_paused());
  CHECK(mrdv_used() == 0);
}

static void test_moqtrun_d23lg_resume_refused_fails_waiters(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_resume_refused_d23);
}

/* An earlier answer does not carry over: after a refused unpause a new
 * SUBSCRIBE waits for its own unpause, sent again, and gets its value. */
static void mtlg_no_preauth_d23(void) {
  mtlg_resume_refused_d23();
  mups_sub(SESS_B, MRDV_S2);
  CHECK(mrdv_is(SESS_B, MRDV_S2, ""));
  CHECK(mtlg_unpauses() == 2);
  mtlg_rok(MUPS_PUB_SID, 0, 8);
  CHECK(mtlg_sok_is(MRDV_S2, 0, 8));
}

static void test_moqtrun_d23lg_no_preauthorized_answer(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_no_preauth_d23);
}

/* The upstream ends while a request waits: the publisher's session goes
 * (INTERNAL_ERROR) -- waiting on the unpause or on the hub's upstream
 * SUBSCRIBE -- or the publisher ends its PUBLISH with PUBLISH_DONE or
 * cancels it. */
static void mtlg_close_d23(void) {
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E0|FIN|"));
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  mups_done(MUPS_PUB_SID, MOQCTL_DONE_TRACK_ENDED);
  wired_moqt_tick(&mtst_hub, 1); /* the PUBLISH_DONE sweep */
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E0|FIN|"));
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MUPS_PUB_SID, 0, 0);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E0|FIN|"));
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E0|FIN|"));
  CHECK(mrdv_used() == 0);
}

static void test_moqtrun_d23lg_upstream_close_fails_waiters(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_close_d23);
}

/* One answer per request: a SUBSCRIBE answered after the unpause ends
 * with PUBLISH_DONE when the publisher goes, never a REQUEST_ERROR. */
static void mtlg_one_answer_d23(void) {
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  mtlg_rok(MUPS_PUB_SID, 0, 9);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mtlg_sok_is(MRDV_S1, 0, 9));
  CHECK(mtlg_no_err(MRDV_S1));
}

static void test_moqtrun_d23lg_one_answer_per_request(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_one_answer_d23);
}

/* ===================== the hub's PUBLISH (9.19.17) ===================== */

/* 9.19.17: a relay that received Objects MUST include LARGEST_OBJECT in
 * the PUBLISH it sends for a SUBSCRIBE_TRACKS; none received, none sent. */
static void mtlg_subtracks_largest_d23(void) {
  moqctl_params  l = mtlg_loc(3, 1);
  moqctl_publish pub;
  mtlg_subtracks(&l, &pub);
  CHECK(mtlg_has(&pub.params, 3, 1));
  mtlg_subtracks(0, &pub);
  CHECK(!moqctl_params_find(&pub.params, MOQCTL_PARAM_LARGEST_OBJECT));
}

/* Before draft-23 the hub's PUBLISH carries no LARGEST_OBJECT. */
static void mtlg_subtracks_largest_d22(void) {
  moqctl_params  l = mtlg_loc(3, 1);
  moqctl_publish pub;
  mtlg_subtracks(&l, &pub);
  CHECK(!moqctl_params_find(&pub.params, MOQCTL_PARAM_LARGEST_OBJECT));
}

static void test_moqtrun_d23lg_subtracks_publish_largest(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_subtracks_largest_d23);
  moqtrun_test_vers(0, MOQVER_CAP_RELAY_LARGEST, mtlg_subtracks_largest_d22);
}

void test_moqtrun_d23lg(void) {
  test_moqtrun_d23lg_subtracks_publish_largest();
  test_moqtrun_d23lg_psn_raises_largest();
  test_moqtrun_d23lg_psn_value_in_answer();
  test_moqtrun_d23lg_ruok_largest_used();
  test_moqtrun_d23lg_paused_pub_waits_resume();
  test_moqtrun_d23lg_paused_sub_resumes_upstream();
  test_moqtrun_d23lg_tstat_paused_fresh();
  test_moqtrun_d23lg_wait_slots_bounded();
  test_moqtrun_d23lg_resume_refused_fails_waiters();
  test_moqtrun_d23lg_no_preauthorized_answer();
  test_moqtrun_d23lg_upstream_close_fails_waiters();
  test_moqtrun_d23lg_one_answer_per_request();
}
