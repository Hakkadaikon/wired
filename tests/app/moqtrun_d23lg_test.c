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

/* A PUBLISHes the awaited track on its request stream MUPS_PUB_SID,
 * paused or not, with LARGEST_OBJECT {g, o} (g ~0: none). */
static void mtlg_pub_now(int paused, u64 g, u64 o) {
  moqctl_ftn    f = mrdv_f();
  moqctl_params p = mtlg_loc(g, o);
  usz           i = g != ~(u64)0;
  p.items[i].type = MOQCTL_PARAM_FORWARD;
  p.items[i].enc  = MOQCTL_PENC_UINT8;
  p.items[i].u8v  = (u8)!paused;
  p.n             = i + 1;
  mtst_publish_p(SESS_A, MUPS_PUB_SID, &f, MUPS_ALIAS, &p);
}

/* The same right after A, B joined (mrdv_init). */
static void mtlg_pub(int paused, u64 g, u64 o) {
  mrdv_init();
  mups_sids();
  mtlg_pub_now(paused, g, o);
}

/* A sends Group g's Objects 0..n-1 on one SUBGROUP stream. */
static void mtlg_objects(u64 g, usz n) {
  u8             buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqdata_subhdr h   = {0};
  usz            off = 0;
  h.type             = 0x30;
  h.track_alias      = MUPS_ALIAS;
  h.group_id         = g;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  for (usz i = 0; i < n; i++) {
    u8 b = (u8)i;
    moqdata_obj_put(
        wired_mspan_of(buf, sizeof buf), &off, 0, wired_span_of(&b, 1));
  }
  mt_feed(&mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(buf, off), 1);
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

/* The unpause's own REQUEST_UPDATE_OK settles the wait, not an earlier
 * answer on the stream: a draft-22 subscriber's NEW_GROUP_REQUEST goes
 * out before the unpause, and its REQUEST_OK leaves the draft-23 request
 * waiting (answers come in order, 9.5). */
static void mtlg_resume_in_order_d23(void) {
  mrdv_init();
  mups_sids();
  mtst_join(SESS_C);
  moqtrun_find_by_wt(&mtst_hub, SESS_C)->ver = MOQVER_D22;
  mups_pub_stream_p(MOQCTL_PARAM_PAUSED, 1); /* DYNAMIC_GROUPS 1 */
  mups_sub_ngr(SESS_C, MRDV_S1, 0);
  CHECK(moqtrun_req_find(&mtst_hub, SESS_A, MUPS_PUB_SID)->upd_out == 2);
  mups_sub(SESS_B, MRDV_S1);
  mtlg_rok(MUPS_PUB_SID, 0, 6);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  mtlg_rok(MUPS_PUB_SID, 0, 7);
  CHECK(mtlg_sok_is(MRDV_S1, 0, 7));
}

static void test_moqtrun_d23lg_paused_pub_waits_resume(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_paused_pub_d23);
  moqtrun_test_vers(0, MOQVER_CAP_RELAY_LARGEST, mtlg_paused_pub_d22);
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_resume_in_order_d23);
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
 * rendezvous slot: one unpause for all of them, and past the session's
 * share of slots a new SUBSCRIBE or TRACK_STATUS is refused
 * EXCESSIVE_LOAD at once. After WIRED_MOQTRUN_UP_WAIT_MS each waiter is
 * refused TIMEOUT (12.3) and its slot freed. */
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
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_UP_WAIT_MS - 1);
  CHECK(mrdv_used() == WIRED_MOQTRUN_RDV_PER_SESSION);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_UP_WAIT_MS);
  CHECK(mrdv_used() == 0 && mrdv_is(SESS_B, MRDV_S1, "E2|FIN|"));
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

/* ============ answers from a usable upstream (7.5) ============ */

/* Type of the which-th message the hub sent on A's stream sid; ~0 if
 * none. */
static u64 mtlg_type_at(u64 sid, usz which) {
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    wired_span               all = wired_span_of(c->payload, c->payload_len);
    usz                      off = 0;
    u64                      type;
    wired_span               body;
    if (c->s != SESS_A || c->stream_id != sid ||
        (c->kind != 3 && c->kind != 12)) {
      continue;
    }
    while (off < all.n &&
           moqctl_peek_type_v(mtst_ver(SESS_A), all, &off, &type, &body) !=
               MOQCTL_INSUFFICIENT) {
      if (which-- == 0) {
        return type;
      }
    }
  }
  return ~(u64)0;
}

/* Request streams of type the hub opened toward A. */
static usz mtlg_sent_to_a(u64 type) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    wired_span               all = wired_span_of(c->payload, c->payload_len);
    usz                      off = 0;
    u64                      t;
    wired_span               body;
    if (c->kind == 1 && c->s == SESS_A &&
        moqctl_peek_type_v(mtst_ver(SESS_A), all, &off, &t, &body) !=
            MOQCTL_INSUFFICIENT) {
      n += t == type;
    }
  }
  return n;
}

/* An unpaused, Established upstream answers at once with the largest of
 * its LARGEST_OBJECT {1,0} and the Objects it delivered ({2,4}). */
static void mtlg_live_d23(void) {
  mtlg_pub(0, 1, 0);
  mtlg_objects(2, 5);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mtlg_sok_is(MRDV_S1, 2, 4));
  CHECK(mtlg_unpauses() == 0);
}

static void test_moqtrun_d23lg_live_answers_at_once(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_live_d23);
}

/* A answers the hub's upstream SUBSCRIBE on sid with LARGEST_OBJECT
 * {g, o}. */
static void mtlg_up_ok(u64 sid, u64 g, u64 o) {
  static moqctl_subscribe_ok ok;
  ok.track_alias = MUPS_ALIAS;
  ok.params      = mtlg_loc(g, o);
  mtst_send(SESS_A, sid, MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
}

/* 7.5: with no upstream the hub subscribes upstream and answers only
 * once it is Established, with the SUBSCRIBE_OK's value. */
static void mtlg_subok_d23(void) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mups_n_up(SESS_A) == 1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  mtlg_up_ok((u64)mups_up_sid(), 1, 0);
  CHECK(mtlg_sok_is(MRDV_S1, 1, 0));
}

static void test_moqtrun_d23lg_upstream_subok_value(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_subok_d23);
}

/* 7.7: a SUBSCRIBE that is not paused never makes the hub subscribe
 * upstream paused (no PAUSED 1, decoded back as FORWARD 0). */
static void mtlg_up_unpaused_d23(void) {
  moqctl_subscribe    m;
  const moqctl_param* fw;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mups_up(SESS_A, 0, &m) >= 0);
  fw = moqctl_params_find(&m.params, MOQCTL_PARAM_FORWARD);
  CHECK(!fw || fw->u8v == 1);
}

static void test_moqtrun_d23lg_upstream_sub_not_paused(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_up_unpaused_d23);
}

/* A SUBSCRIBE waiting for a publisher is answered by an unpaused PUBLISH
 * with its value; by a paused one only after the unpause, which follows
 * the PUBLISH's own REQUEST_OK on its stream. */
static void mtlg_publish_wakes_d23(void) {
  mrdv_init();
  mups_sids();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  mtlg_pub_now(0, 4, 2);
  CHECK(mtlg_sok_is(MRDV_S1, 4, 2));
  mrdv_init();
  mups_sids();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  mtlg_pub_now(1, 4, 2);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  CHECK(mtlg_type_at(MUPS_PUB_SID, 0) == MOQCTL_T_REQUEST_OK);
  CHECK(mtlg_type_at(MUPS_PUB_SID, 1) == MOQTSTAT_T_REQUEST_UPDATE);
  wired_moqt_tick(&mtst_hub, 1000); /* past the RENDEZVOUS_TIMEOUT */
  mtlg_rok(MUPS_PUB_SID, 4, 3);
  CHECK(mtlg_sok_is(MRDV_S1, 4, 3));
}

static void test_moqtrun_d23lg_publish_wakes_waiter(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_publish_wakes_d23);
}

/* A later answer on one subscription never goes below an earlier one:
 * REQUEST_UPDATE_OK after SUBSCRIBE_OK {2,0} carries {2,0}, then the
 * newer Object. */
static void mtlg_monotone_d23(void) {
  moqctl_params u = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 9);
  moqctl_params p;
  mtlg_pub(0, 2, 0);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mtlg_sok_is(MRDV_S1, 2, 0));
  mtup_update(SESS_B, MRDV_S1, &u);
  CHECK(mtlg_answer(SESS_B, MRDV_S1, 1, &p) && mtlg_has(&p, 2, 0));
  mtlg_objects(2, 3);
  mtup_update(SESS_B, MRDV_S1, &u);
  CHECK(mtlg_answer(SESS_B, MRDV_S1, 1, &p) && mtlg_has(&p, 2, 2));
}

static void test_moqtrun_d23lg_answers_monotone(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_monotone_d23);
}

/* Never above what the upstream sent: LARGEST_OBJECT {1,3} and Objects up
 * to exactly {1,3} answer {1,3}. */
static void mtlg_never_above_d23(void) {
  mtlg_pub(0, 1, 3);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mtlg_sok_is(MRDV_S1, 1, 3));
  mtlg_objects(1, 4);
  mups_sub(SESS_B, MRDV_S2);
  CHECK(mtlg_sok_is(MRDV_S2, 1, 3));
}

static void test_moqtrun_d23lg_never_above_upstream(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_never_above_d23);
}

/* 9.19.17: no Object and no LARGEST_OBJECT received, none sent --
 * SUBSCRIBE_OK and TRACK_STATUS_OK alike; one Object, then always. */
static void mtlg_iff_seen_d23(void) {
  moqctl_params p;
  mtlg_pub(0, ~(u64)0, 0);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mtlg_answer(SESS_B, MRDV_S1, 0, &p));
  CHECK(!moqctl_params_find(&p, MOQCTL_PARAM_LARGEST_OBJECT));
  mtlg_tstat(MRDV_S2);
  CHECK(mtlg_answer(SESS_B, MRDV_S2, 1, &p));
  CHECK(!moqctl_params_find(&p, MOQCTL_PARAM_LARGEST_OBJECT));
  mtlg_objects(0, 1);
  mtlg_tstat(MRDV_S2 + 4);
  CHECK(mtlg_rok_is(MRDV_S2 + 4, 0, 0));
}

static void test_moqtrun_d23lg_include_iff_seen(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_iff_seen_d23);
}

/* An Object older than the Largest ({2,9} after {3,0}) does not lower
 * it. */
static void mtlg_late_d23(void) {
  mtlg_pub(0, 3, 0);
  mtlg_objects(2, 10);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mtlg_sok_is(MRDV_S1, 3, 0));
}

static void test_moqtrun_d23lg_late_object_keeps_largest(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_late_d23);
}

/* The hub's upstream SUBSCRIBE refused DOES_NOT_EXIST: the waiter gets
 * that code, no SUBSCRIBE_OK, no LARGEST_OBJECT. */
static void mtlg_up_refused_d23(void) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mtst_pub_err(SESS_A, (u64)mups_up_sid(), MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E10|FIN|"));
}

static void test_moqtrun_d23lg_upstream_refused_fails_waiters(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_up_refused_d23);
}

/* A request for a track whose upstream ended (its PUBLISH done, or its
 * publisher gone) is refused, never answered from the old Largest. */
static void mtlg_gone_d23(void) {
  mtlg_pub(0, 1, 0);
  mups_done(MUPS_PUB_SID, MOQCTL_DONE_TRACK_ENDED);
  wired_moqt_tick(&mtst_hub, 1);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E10|FIN|"));
  mtlg_pub(0, 1, 0);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E10|FIN|"));
}

static void test_moqtrun_d23lg_gone_track_refused(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_gone_d23);
}

/* The hub sends no TRACK_STATUS upstream: a TRACK_STATUS while its
 * upstream SUBSCRIBE is unanswered is not answered OK from anything, and
 * nothing but that SUBSCRIBE goes to A. */
static void mtlg_no_ts_d23(void) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mtlg_tstat(MRDV_S2);
  CHECK(mrdv_is(SESS_B, MRDV_S2, "E10|FIN|"));
  CHECK(mups_n_up(SESS_A) == 1);
  CHECK(mtlg_sent_to_a(MOQTSTAT_T_TRACK_STATUS) == 0);
}

static void test_moqtrun_d23lg_no_ts_before_established(void) {
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_no_ts_d23);
}

/* ============ edges of the wait (7.5, 9.5, 9.10) ============ */

/* A PUBLISH on the control stream has no request stream to unpause on:
 * the hub sends nothing, the request waits until the PUBLISH ends.
 * shortcut: no answer before that; such a PUBLISH predates request
 * streams and no draft-23 publisher sends one. */
static void mtlg_ctl_pub_d23(void) {
  moqctl_ftn    f = mrdv_f();
  moqctl_params p = mtlg_loc(0, 5);
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  p.items[1].type = MOQCTL_PARAM_FORWARD;
  p.items[1].enc  = MOQCTL_PENC_UINT8;
  p.items[1].u8v  = 0;
  p.n             = 2;
  mtst_publish_p(SESS_A, ca, &f, MUPS_ALIAS, &p);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  CHECK(mrdv_used() == 1);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E0|FIN|"));
}

/* A REQUEST_ERROR that does not decode closes the publisher's session,
 * and the waiter gets INTERNAL_ERROR; a REQUEST_OK after the PUBLISH
 * ended answers nothing more. */
static void mtlg_bad_answer_d23(void) {
  static const u8 junk[] = {0xFF};
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  mtrq_raw(SESS_A, MUPS_PUB_SID, MOQCTL_T_REQUEST_ERROR, junk, sizeof junk);
  CHECK(moqtrun_test_count_kind(11) == 1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E0|FIN|"));
  mtlg_pub(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  mups_done(MUPS_PUB_SID, MOQCTL_DONE_TRACK_ENDED);
  wired_moqt_tick(&mtst_hub, 1);
  mtlg_rok(MUPS_PUB_SID, 0, 9);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E0|FIN|"));
}

/* 9.10: a PUBLISH_STATE_NOTIFY whose parameters do not decode is
 * informative only: nothing counted, the session stays. */
static void mtlg_bad_psn_d23(void) {
  static const u8 junk[] = {0x01, 0x09, 0xFF};
  mtlg_pub(0, 0, 5);
  mtrq_raw(
      SESS_A, MUPS_PUB_SID, MOQCTL_T_PUBLISH_STATE_NOTIFY, junk, sizeof junk);
  CHECK(mtlg_top_is(0, 5));
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* A draft-22 publisher's refused unpause fails the draft-23 waiter, and
 * its PUBLISH stays paused as on draft-23 (the refused REQUEST_UPDATE
 * changed nothing; draft-22 9.5 and draft-23 9.5 alike end the
 * subscription with PUBLISH_DONE UPDATE_FAILED after it). */
static void mtlg_d22_pub_refused_d23(void) {
  mrdv_init();
  mups_sids();
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = MOQVER_D22;
  mtlg_pub_now(1, 0, 5);
  mups_sub(SESS_B, MRDV_S1);
  mtst_pub_err(SESS_A, MUPS_PUB_SID, MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E3|FIN|"));
  CHECK(mtlg_paused());
}

/* A body longer than a slot keeps is refused EXCESSIVE_LOAD, not held. */
static void mtlg_long_body_d23(void) {
  static u8     tok[1006];
  moqctl_ftn    f  = mrdv_f();
  moqctl_params p  = {0};
  tok[0]           = 0x03; /* USE_VALUE */
  tok[1]           = 0x01;
  p.items[0].type  = MOQCTL_PARAM_AUTHORIZATION_TOKEN;
  p.items[0].enc   = MOQCTL_PENC_TOKEN;
  p.items[0].bytes = wired_span_of(tok, sizeof tok);
  p.n              = 1;
  mtlg_pub(1, 0, 5);
  mtst_subscribe_p(SESS_B, MRDV_S1, &f, mtst_rid += 4, &p);
  CHECK(mrdv_err(SESS_B, MRDV_S1).error_code == MOQCTL_ERR_EXCESSIVE_LOAD);
  CHECK(mrdv_used() == 0);
}

/* A wait for the unpause is not the upstream SUBSCRIBE's waiter: B held
 * for an announced track takes C's paused PUBLISH and waits for its
 * unpause; A refusing the hub's upstream SUBSCRIBE leaves it waiting. */
static void mtlg_up_refusal_spares_d23(void) {
  moqctl_ftn    f = mrdv_f();
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  mups_init();
  mtst_join(SESS_C);
  mups_sub(SESS_B, MRDV_S1);
  u64 up = (u64)mups_up_sid();
  mtst_publish_p(SESS_C, 16, &f, MUPS_ALIAS, &p);
  mtst_pub_err(SESS_A, up, MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  mtst_pub_ok(SESS_C, 16);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
}

/* draft-19/22 too: the hub answers a PUBLISH with REQUEST_OK before it
 * sends an unpause on that stream -- only a subscription established
 * with PUBLISH can be updated (draft-23 9.5, draft-22 9.5). A held
 * SUBSCRIBE met by a paused PUBLISH therefore waits for the REQUEST_OK. */
static void mtlg_d22_order(void) {
  mrdv_init();
  mups_sids();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  mtlg_pub_now(1, 4, 2);
  CHECK(mtlg_type_at(MUPS_PUB_SID, 0) == MOQCTL_T_REQUEST_OK);
  CHECK(mtlg_type_at(MUPS_PUB_SID, 1) == MOQTSTAT_T_REQUEST_UPDATE);
}

static void test_moqtrun_d23lg_wait_edges(void) {
  moqtrun_test_vers(
      MOQVER_CAP_RANGE_FILTERS, MOQVER_CAP_RELAY_LARGEST, mtlg_d22_order);
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_ctl_pub_d23);
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_bad_answer_d23);
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_bad_psn_d23);
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_d22_pub_refused_d23);
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_long_body_d23);
  moqtrun_test_vers(MOQVER_CAP_RELAY_LARGEST, 0, mtlg_up_refusal_spares_d23);
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
  test_moqtrun_d23lg_live_answers_at_once();
  test_moqtrun_d23lg_upstream_subok_value();
  test_moqtrun_d23lg_upstream_sub_not_paused();
  test_moqtrun_d23lg_publish_wakes_waiter();
  test_moqtrun_d23lg_answers_monotone();
  test_moqtrun_d23lg_never_above_upstream();
  test_moqtrun_d23lg_include_iff_seen();
  test_moqtrun_d23lg_late_object_keeps_largest();
  test_moqtrun_d23lg_upstream_refused_fails_waiters();
  test_moqtrun_d23lg_gone_track_refused();
  test_moqtrun_d23lg_no_ts_before_established();
  test_moqtrun_d23lg_wait_edges();
}
