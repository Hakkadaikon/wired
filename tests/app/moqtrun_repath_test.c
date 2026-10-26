/* A subscription survives a publisher change: when the hub's upstream
 * SUBSCRIBE ends on the publisher's side (PUBLISH_DONE GOING_AWAY or
 * INTERNAL_ERROR, a reset of the hub's stream, the publisher's session
 * closing), its downstream subscriptions wait up to
 * WIRED_MOQTRUN_RDV_MAX_MS for another announcer instead of ending, and
 * are re-attached silently under the Track Alias they hold
 * (draft-ietf-moq-transport-22 7.6, 7.6.1). Every other end goes
 * downstream at once. One upstream per Track: announcers are tried one at
 * a time. Shares the fixtures of moqtrun_upsub_test.c,
 * moqtrun_rdv_test.c, moqtrun_ns_test.c, moqtrun_drain_test.c and
 * moqtrun_upd_test.c (same unity TU).
 *
 * Sessions: A publishes (announces chat/room1), B is another announcer,
 * C and D subscribe, MRP_E is a third announcer or a new subscriber. */

static wired_wt_session* const MRP_E = (wired_wt_session*)(usz)5;

/* A's upstream stream carrying C's and D's subscription. */
static u64 mrp_up_a;

/* C and D receive chat/room1/alice through the hub's SUBSCRIBE to A. */
static void mrp_init(void) {
  mups_init();
  mtst_join(SESS_C);
  mtst_join(SESS_D);
  mtst_join(MRP_E);
  mups_sub(SESS_C, MRDV_S1);
  mups_sub(SESS_D, MRDV_S1);
  mrp_up_a = (u64)mups_up_sid();
  mups_ok(mrp_up_a);
}

static void mrp_announce(wired_wt_session* s) {
  mtns_pub(s, MRDV_S1, "chat/room1");
}

/* A withdraws its PUBLISH_NAMESPACE (cancels it) and announces again. */
static void mrp_reannounce_a(void) {
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MRDV_S1, 0, 0);
  mtns_pub(SESS_A, MRDV_S2, "chat/room1");
}

/* The which-th upstream SUBSCRIBE toward s; -1 if none. */
static i64 mrp_up(wired_wt_session* s, usz which) {
  moqctl_subscribe m;
  return mups_up(s, which, &m);
}

static void mrp_ok(wired_wt_session* s, i64 sid) {
  static moqctl_subscribe_ok ok;
  ok.track_alias = MUPS_ALIAS;
  mtst_send(s, (u64)sid, MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
}

/* Group g from s on its uni stream sid under MUPS_ALIAS: one Object,
 * then one with status unless status is Normal; FINed. */
static void mrp_group(wired_wt_session* s, u64 sid, u64 g, u64 status) {
  u8             buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqdata_subhdr h   = {0};
  usz            off = 0;
  u8             b   = 0x5a;
  wired_mspan    out = wired_mspan_of(buf, sizeof buf);
  h.type             = 0x30;
  h.track_alias      = MUPS_ALIAS;
  h.group_id         = g;
  moqdata_subhdr_put(out, &off, &h);
  moqdata_obj_put(out, &off, 0, wired_span_of(&b, 1));
  if (status != MOQDATA_STATUS_NORMAL) {
    moqdata_obj_put_status(out, &off, 0, status);
  }
  wired_moqt_on_stream_data(&mtst_hub, s, sid, wired_span_of(buf, off), 1);
}

/* 1 iff s's Objects reached C and D under the aliases they hold. */
static int mrp_relayed(wired_wt_session* s) {
  mrp_group(s, MUPS_DATA_SID, 0, MOQDATA_STATUS_NORMAL);
  return mups_relayed_alias(SESS_C) == mrdv_alias(SESS_C, MRDV_S1) &&
         mups_relayed_alias(SESS_D) == mrdv_alias(SESS_D, MRDV_S1);
}

/* The last mrp_dones PUBLISH_DONE's Stream Count. */
static u64 mrp_count;

/* PUBLISH_DONEs on s's request stream; *st the last one's status,
 * mrp_count its Stream Count. */
static usz mrp_dones(wired_wt_session* s, u64* st) {
  usz n = 0;
  u64 count;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    u64                      x;
    if (c->s != s || c->stream_id != MRDV_S1) {
      continue;
    }
    if (c->kind != 3 && c->kind != 12) {
      continue;
    }
    x = mtdr_done_in(c, &count);
    if (x == ~(u64)0) {
      continue;
    }
    n++;
    *st       = x;
    mrp_count = count;
  }
  return n;
}

/* 1 iff C and D each got exactly one PUBLISH_DONE, with status and
 * Stream Count streams. */
static int mrp_done_once_n(u64 status, u64 streams) {
  u64 sc = ~(u64)0, sd = ~(u64)0, nc = ~(u64)0;
  int ok = mrp_dones(SESS_C, &sc) == 1;
  nc     = mrp_count;
  ok     = ok && mrp_dones(SESS_D, &sd) == 1;
  ok     = ok && nc == streams && mrp_count == streams;
  if (!ok || sc != status || sd != status) {
    printf(
        "  done C %llx/%llu D %llx/%llu want %llx/%llu\n",
        (unsigned long long)sc, (unsigned long long)nc, (unsigned long long)sd,
        (unsigned long long)mrp_count, (unsigned long long)status,
        (unsigned long long)streams);
  }
  return ok && sc == status && sd == status;
}

/* No Group was relayed: Stream Count 0. */
static int mrp_done_once(u64 status) { return mrp_done_once_n(status, 0); }

static int mrp_no_done(void) {
  u64 st;
  return mrp_dones(SESS_C, &st) == 0 && mrp_dones(SESS_D, &st) == 0;
}

/* 1 iff the hub reset its stream sid toward s. */
static int mrp_reset_on(wired_wt_session* s, i64 sid) {
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind == 7 && g_calls[i].s == s &&
        g_calls[i].stream_id == (u64)sid) {
      return 1;
    }
  }
  return 0;
}

/* The ways A can end the upstream. */
enum { MRP_GA, MRP_IE, MRP_RESET, MRP_CLOSE, MRP_ENDS };

static void mrp_end(int how) {
  if (how == MRP_GA) {
    mups_done(mrp_up_a, MOQCTL_DONE_GOING_AWAY);
  }
  if (how == MRP_IE) {
    mups_done(mrp_up_a, MOQCTL_DONE_INTERNAL_ERROR);
  }
  if (how == MRP_RESET) {
    wired_moqt_on_stream_reset(&mtst_hub, SESS_A, mrp_up_a, 1, 0);
  }
  if (how == MRP_CLOSE) {
    wired_moqt_on_session_close(&mtst_hub, SESS_A);
  }
}

/* A GOING_AWAY from A, B announced: B gets one SUBSCRIBE in the same
 * dispatch, and on its SUBSCRIBE_OK C and D get B's Objects under the
 * aliases they hold -- no second SUBSCRIBE_OK, REQUEST_ERROR or
 * PUBLISH_DONE. */
static void test_moqtrun_repath_takeover(void) {
  i64 sid;
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  sid = mrp_up(SESS_B, 0);
  CHECK(sid >= 0);
  CHECK(mrp_up(SESS_B, 1) < 0);
  mrp_ok(SESS_B, sid);
  CHECK(mrp_relayed(SESS_B));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
  CHECK(mrdv_is(SESS_D, MRDV_S1, "SOK|"));
  CHECK(mrdv_used() == 0);
  CHECK(mups_used() == 1);
}

/* Each publisher-side end that re-paths: GOING_AWAY, INTERNAL_ERROR, a
 * reset of the hub's stream, A's session closing. */
static void test_moqtrun_repath_each_end(void) {
  for (int how = 0; how < MRP_ENDS; how++) {
    int fails = wired_test_fails;
    i64 sid;
    mrp_init();
    mrp_announce(SESS_B);
    mrp_end(how);
    CHECK(mrp_no_done());
    sid = mrp_up(SESS_B, 0);
    CHECK(sid >= 0);
    mrp_ok(SESS_B, sid);
    CHECK(mrp_relayed(SESS_B));
    if (wired_test_fails != fails) {
      printf("  ^ end %d\n", how);
    }
  }
}

/* The hub itself closing A's session waits for a new path as A's own
 * close does: after a malformed GOAWAY (PROTOCOL_VIOLATION) and after
 * A's GOAWAY drain runs out. B is asked once the session is gone. */
static void test_moqtrun_repath_hub_closes(void) {
  static const u8 bad[] = {0x05};
  u64             code  = 0;
  for (int drain = 0; drain < 2; drain++) {
    int fails = wired_test_fails;
    mrp_init();
    mrp_announce(SESS_B);
    if (drain) {
      wired_moqt_on_session_draining(&mtst_hub, SESS_A);
      wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_DRAIN_TIMEOUT_MS);
      wired_moqt_tick(
          &mtst_hub,
          WIRED_MOQTRUN_DRAIN_TIMEOUT_MS + WIRED_MOQTRUN_GOAWAY_GRACE_MS + 1);
    } else {
      mtrq_raw(SESS_A, mtdr_ctl(SESS_A), MOQCTL_T_GOAWAY, bad, sizeof bad);
    }
    CHECK(mtdr_closes(SESS_A, &code) == 1);
    /* the transport reports the close a tick later */
    wired_moqt_tick(
        &mtst_hub, drain ? WIRED_MOQTRUN_DRAIN_TIMEOUT_MS +
                               WIRED_MOQTRUN_GOAWAY_GRACE_MS + 2
                         : 1);
    wired_moqt_on_session_close(&mtst_hub, SESS_A);
    CHECK(mrp_no_done());
    CHECK(mups_n_up(SESS_B) == 1);
    mrp_ok(SESS_B, mrp_up(SESS_B, 0));
    CHECK(mrp_relayed(SESS_B));
    if (wired_test_fails != fails) {
      printf("  ^ drain %d\n", drain);
    }
  }
}

/* Every other PUBLISH_DONE status goes downstream at once, spelled for
 * the subscriber's draft; B is not asked. */
static void test_moqtrun_repath_final_status(void) {
  static const u64 st[] = {
      MOQCTL_DONE_TRACK_ENDED,
      0x1 /* UNAUTHORIZED */,
      0x6 /* EXPIRED */,
      0x5 /* TOO_FAR_BEHIND */,
      MOQCTL_DONE_SUBSCRIPTION_ENDED,
      0x9 /* EXCESSIVE_LOAD */};
  for (usz i = 0; i < sizeof st / sizeof st[0]; i++) {
    int fails = wired_test_fails;
    mrp_init();
    mrp_announce(SESS_B);
    mups_done(mrp_up_a, st[i]);
    CHECK(mrp_done_once(moqctl_publish_done_for(g_moqtrun_test_ver, st[i])));
    CHECK(mups_n_up(SESS_B) == 0);
    CHECK(mrdv_used() == 0);
    if (wired_test_fails != fails) {
      printf("  ^ status %llx\n", (unsigned long long)st[i]);
    }
  }
}

/* While waiting, nothing at all happens on C's or D's request stream. */
static void test_moqtrun_repath_silent_wait(void) {
  mrp_init();
  mrp_end(MRP_CLOSE);
  CHECK(mrp_no_done());
  moqtrun_test_reset();
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS - 1);
  CHECK(mrdv_is(SESS_C, MRDV_S1, ""));
  CHECK(mrdv_is(SESS_D, MRDV_S1, ""));
}

/* An announce arriving within the wait is subscribed at once. */
static void test_moqtrun_repath_late_announce(void) {
  i64 sid;
  mrp_init();
  mrp_end(MRP_CLOSE);
  wired_moqt_tick(&mtst_hub, 1000);
  mrp_announce(SESS_B);
  sid = mrp_up(SESS_B, 0);
  CHECK(sid >= 0);
  mrp_ok(SESS_B, sid);
  CHECK(mrp_relayed(SESS_B));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
}

/* Nobody announces: exactly one PUBLISH_DONE each at the deadline, and a
 * later announce re-attaches no one. */
static void test_moqtrun_repath_expiry(void) {
  mrp_init();
  mrp_end(MRP_GA);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS - 1);
  CHECK(mrp_no_done());
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once(MOQCTL_DONE_GOING_AWAY));
  CHECK(mrdv_used() == 0);
  mrp_announce(SESS_B);
  CHECK(mups_n_up(SESS_B) == 0);
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|Tb|FIN|"));
}

/* The expiry PUBLISH_DONE carries the original end's status: a reset or a
 * close reads INTERNAL_ERROR. */
static void test_moqtrun_repath_expiry_status(void) {
  static const u64 want[MRP_ENDS] = {
      MOQCTL_DONE_GOING_AWAY, MOQCTL_DONE_INTERNAL_ERROR,
      MOQCTL_DONE_INTERNAL_ERROR, MOQCTL_DONE_INTERNAL_ERROR};
  for (int how = 0; how < MRP_ENDS; how++) {
    int fails = wired_test_fails;
    mrp_init();
    mrp_end(how);
    wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
    CHECK(mrp_done_once(want[how]));
    if (wired_test_fails != fails) {
      printf("  ^ end %d\n", how);
    }
  }
}

/* B never answers: the deadline still ends C and D, B's SUBSCRIBE is
 * cancelled in the same tick, and B's late SUBSCRIBE_OK is ignored. */
static void test_moqtrun_repath_deadline_beats_pending(void) {
  i64 sid;
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  sid = mrp_up(SESS_B, 0);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once(MOQCTL_DONE_GOING_AWAY));
  CHECK(mrp_reset_on(SESS_B, sid));
  CHECK(mups_used() == 0);
  mrp_ok(SESS_B, sid);
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|Tb|FIN|"));
  CHECK(mups_used() == 0);
}

/* Trying another announcer never moves the deadline. */
static void test_moqtrun_repath_deadline_fixed(void) {
  i64 sid;
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  sid = mrp_up(SESS_B, 0);
  wired_moqt_tick(&mtst_hub, 1000);
  mtst_pub_err(SESS_B, (u64)sid, MOQCTL_ERR_UNAUTHORIZED);
  wired_moqt_tick(&mtst_hub, 1200);
  mrp_reannounce_a();
  CHECK(mups_n_up(SESS_A) == 2);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS - 1);
  CHECK(mrp_no_done());
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once(MOQCTL_DONE_GOING_AWAY));
}

/* B's refusal is not forwarded: C and D keep waiting. */
static void test_moqtrun_repath_refusal_hidden(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_IE);
  mtst_pub_err(SESS_B, (u64)mrp_up(SESS_B, 0), MOQCTL_ERR_UNAUTHORIZED);
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
  CHECK(mrdv_is(SESS_D, MRDV_S1, "SOK|"));
  CHECK(mrdv_used() == 2);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once(MOQCTL_DONE_INTERNAL_ERROR));
}

/* B and E announced: one SUBSCRIBE at a time; the other is asked in the
 * dispatch of the first one's refusal, and serves C and D. */
static void test_moqtrun_repath_failover(void) {
  wired_wt_session* first;
  wired_wt_session* other;
  mrp_init();
  mrp_announce(SESS_B);
  mrp_announce(MRP_E);
  mrp_end(MRP_GA);
  CHECK(mups_n_up(SESS_B) + mups_n_up(MRP_E) == 1);
  first = mups_n_up(SESS_B) ? SESS_B : MRP_E;
  other = first == SESS_B ? MRP_E : SESS_B;
  mtst_pub_err(first, (u64)mrp_up(first, 0), MOQCTL_ERR_UNAUTHORIZED);
  CHECK(mups_n_up(first) == 1);
  CHECK(mups_n_up(other) == 1);
  mrp_ok(other, mrp_up(other, 0));
  CHECK(mrp_relayed(other));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
}

/* The publisher that ended the track is not asked again until it
 * announces anew. */
static void test_moqtrun_repath_ender_skipped(void) {
  mrp_init();
  mrp_end(MRP_GA);
  CHECK(mups_n_up(SESS_A) == 1);
  mrp_reannounce_a();
  CHECK(mups_n_up(SESS_A) == 2);
}

/* B refused: only a PUBLISH_NAMESPACE of B's covering the track makes B
 * worth asking again in this wait, an unrelated one does not. */
static void test_moqtrun_repath_untry_covering(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  mtst_pub_err(SESS_B, (u64)mrp_up(SESS_B, 0), MOQCTL_ERR_UNAUTHORIZED);
  mtns_pub(SESS_B, MRDV_S2, "other/room9");
  CHECK(mups_n_up(SESS_B) == 1);
  mtns_pub(SESS_B, MRDV_S2 + 4, "chat");
  CHECK(mups_n_up(SESS_B) == 2);
}

/* C leaves during the wait: D is re-attached, C never again. */
static void test_moqtrun_repath_leave(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_C, MRDV_S1, 0, 0);
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  mrp_group(SESS_B, MUPS_DATA_SID, 0, MOQDATA_STATUS_NORMAL);
  CHECK(mups_relayed_alias(SESS_D) == mrdv_alias(SESS_D, MRDV_S1));
  CHECK(mups_relayed_alias(SESS_C) == ~(u64)0);
  wired_moqt_tick(&mtst_hub, 2 * WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|RST1|"));
}

/* Everyone leaves while B's SUBSCRIBE is pending: it is cancelled, and no
 * PUBLISH_DONE goes anywhere. */
static void test_moqtrun_repath_all_leave(void) {
  i64 sid;
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  sid = mrp_up(SESS_B, 0);
  wired_moqt_on_session_close(&mtst_hub, SESS_C);
  CHECK(!mrp_reset_on(SESS_B, sid));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_D, MRDV_S1, 0, 0);
  CHECK(mrp_reset_on(SESS_B, sid));
  CHECK(mups_used() == 0);
  CHECK(mrdv_used() == 0);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrdv_is(SESS_D, MRDV_S1, "SOK|RST1|"));
}

/* B withdrawing its namespace after SUBSCRIBE_OK leaves the upstream. */
static void test_moqtrun_repath_withdraw_keeps(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MRDV_S1, 0, 0);
  CHECK(mups_used() == 1);
  CHECK(mrp_relayed(SESS_B));
}

/* B's session closes before it answers: its entry goes with no io, C and
 * D keep the same deadline, and A announcing anew is asked. */
static void test_moqtrun_repath_new_closes(void) {
  i64 sid;
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  sid = mrp_up(SESS_B, 0);
  wired_moqt_tick(&mtst_hub, 500);
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  CHECK(mups_used() == 0);
  CHECK(!mrp_reset_on(SESS_B, sid));
  CHECK(mrdv_used() == 2);
  mrp_reannounce_a();
  CHECK(mups_n_up(SESS_A) == 2);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS - 1);
  CHECK(mrp_no_done());
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once(MOQCTL_DONE_GOING_AWAY));
}

/* After the switch one upstream remains, and A's stray Objects reach no
 * one. */
static void test_moqtrun_repath_one_upstream(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  CHECK(mups_used() == 1);
  mrp_group(SESS_A, MUPS_DATA_SID, 0, MOQDATA_STATUS_NORMAL);
  CHECK(mups_relayed_alias(SESS_C) == ~(u64)0);
  CHECK(mups_relayed_alias(SESS_D) == ~(u64)0);
}

/* Only C subscribed; B's SUBSCRIBE is cancelled when C leaves, and its
 * late SUBSCRIBE_OK neither answers a new subscriber E nor claims the
 * track -- A's answer to the SUBSCRIBE made for E does. */
static void test_moqtrun_repath_stale_ok(void) {
  i64 sb, sa;
  mups_init();
  mtst_join(SESS_C);
  mtst_join(MRP_E);
  mups_sub(SESS_C, MRDV_S1);
  mrp_up_a = (u64)mups_up_sid();
  mups_ok(mrp_up_a);
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  sb = mrp_up(SESS_B, 0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_C, MRDV_S1, 0, 0);
  CHECK(mrp_reset_on(SESS_B, sb));
  mups_sub(MRP_E, MRDV_S1);
  sa = mrp_up(SESS_A, 1);
  CHECK(sa >= 0);
  mrp_ok(SESS_B, sb);
  CHECK(mrdv_is(MRP_E, MRDV_S1, ""));
  mrp_ok(SESS_A, sa);
  CHECK(mrdv_is(MRP_E, MRDV_S1, "SOK|"));
  mrp_group(SESS_A, MUPS_DATA_SID + 4, 0, MOQDATA_STATUS_NORMAL);
  CHECK(mups_relayed_alias(MRP_E) == mrdv_alias(MRP_E, MRDV_S1));
}

/* The new upstream ends again: a fresh wait, and A -- tried in the first
 * one -- is asked. */
static void test_moqtrun_repath_ends_again(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  wired_moqt_tick(&mtst_hub, 1000);
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  CHECK(mups_n_up(SESS_A) == 2);
  wired_moqt_tick(&mtst_hub, 1000 + WIRED_MOQTRUN_RDV_MAX_MS - 1);
  CHECK(mrp_no_done());
  wired_moqt_tick(&mtst_hub, 1000 + WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once(MOQCTL_DONE_INTERNAL_ERROR));
}

/* Stream Count covers the whole subscription: a Group from A, the wait
 * (its expiry counts A's stream), and after a re-link a Group from B,
 * whose TRACK_ENDED then counts both. */
static void test_moqtrun_repath_stream_count(void) {
  static moqctl_publish_done d;
  i64                        sid;
  mrp_init();
  mrp_group(SESS_A, MUPS_DATA_SID, 0, MOQDATA_STATUS_NORMAL);
  mrp_end(MRP_GA);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once_n(MOQCTL_DONE_GOING_AWAY, 1));
  mrp_init();
  mrp_announce(SESS_B);
  mrp_group(SESS_A, MUPS_DATA_SID, 0, MOQDATA_STATUS_NORMAL);
  mrp_end(MRP_GA);
  sid = mrp_up(SESS_B, 0);
  mrp_ok(SESS_B, sid);
  mrp_group(SESS_B, MUPS_DATA_SID, 1, MOQDATA_STATUS_NORMAL);
  d.status_code  = MOQCTL_DONE_TRACK_ENDED;
  d.stream_count = 1;
  mtst_send(SESS_B, (u64)sid, MOQCTL_T_PUBLISH_DONE, mups_enc_done, &d);
  CHECK(mrp_done_once_n(
      moqctl_publish_done_for(g_moqtrun_test_ver, MOQCTL_DONE_TRACK_ENDED), 2));
}

/* A wait's PUBLISH_DONE status and Stream Count are the ones stored when
 * its slot is claimed, never what a free slot held before (freestanding
 * memory starts unzeroed; a plain waiter's claim leaves both unset). */
static void test_moqtrun_repath_done_fields_set_at_claim(void) {
  mrp_init();
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (!mtst_hub.rdv[i].in_use) {
      mtst_hub.rdv[i].done_status = 0x7777;
      mtst_hub.rdv[i].done_count  = 99;
    }
  }
  mrp_group(SESS_A, MUPS_DATA_SID, 0, MOQDATA_STATUS_NORMAL);
  mrp_end(MRP_GA);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once_n(MOQCTL_DONE_GOING_AWAY, 1));
}

/* A GOAWAY drain running out while C and D wait ends them with
 * PUBLISH_DONE GOING_AWAY at the flush (the wait is over: nothing more
 * at its deadline). */
static void test_moqtrun_repath_drain_flush(void) {
  mrp_init();
  mrp_end(MRP_IE);
  CHECK(wired_moqt_goaway(&mtst_hub, mtst_z("https://h/b"), 100) > 0);
  wired_moqt_tick(&mtst_hub, 100);
  CHECK(mrp_done_once(MOQCTL_DONE_GOING_AWAY));
  CHECK(mrdv_used() == 0);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once(MOQCTL_DONE_GOING_AWAY));
}

/* Ticks long past the deadline send no second PUBLISH_DONE. */
static void test_moqtrun_repath_done_once(void) {
  mrp_init();
  mrp_end(MRP_GA);
  CHECK(mrp_no_done());
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  wired_moqt_tick(&mtst_hub, 2 * WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrp_done_once(MOQCTL_DONE_GOING_AWAY));
}

/* A new subscriber E rides B's pending SUBSCRIBE: E gets SUBSCRIBE_OK or
 * REQUEST_ERROR from it, C and D neither. */
static void test_moqtrun_repath_fresh_rides(void) {
  i64 sid;
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  mups_sub(MRP_E, MRDV_S1);
  CHECK(mups_n_up(SESS_B) == 1);
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  CHECK(mrdv_is(MRP_E, MRDV_S1, "SOK|"));
  CHECK(mrp_relayed(SESS_B));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  mups_sub(MRP_E, MRDV_S1);
  sid = mrp_up(SESS_B, 0);
  mtst_pub_err(SESS_B, (u64)sid, MOQCTL_ERR_UNAUTHORIZED);
  CHECK(mrdv_is(MRP_E, MRDV_S1, "E1|FIN|"));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
  CHECK(mrdv_used() == 2);
}

/* B's own new SUBSCRIBE does not ride the hub's pending SUBSCRIBE to B:
 * with no other announcer it is DOES_NOT_EXIST at once. */
static void test_moqtrun_repath_fresh_own_upstream(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  mups_sub(SESS_B, MRDV_S2);
  CHECK(mrdv_is(SESS_B, MRDV_S2, "E10|FIN|"));
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  CHECK(mrdv_is(SESS_B, MRDV_S2, "E10|FIN|"));
}

/* Nor with RENDEZVOUS_TIMEOUT: the hold never resolves to the track the
 * hub's SUBSCRIBE to B claims, and times out at its deadline. */
static void test_moqtrun_repath_fresh_own_upstream_rt(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  mrdv_hold(SESS_B, MRDV_S2, 1000);
  CHECK(mrdv_is(SESS_B, MRDV_S2, ""));
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  CHECK(mrdv_is(SESS_B, MRDV_S2, ""));
  CHECK(mrp_relayed(SESS_B));
  wired_moqt_tick(&mtst_hub, 1000);
  CHECK(mrdv_is(SESS_B, MRDV_S2, "E2|FIN|"));
}

/* Another announcer (E) keeps B's own SUBSCRIBE (no RENDEZVOUS_TIMEOUT)
 * waiting on the hub's SUBSCRIBE to B; when that resolves to B's own track
 * the hold is answered DOES_NOT_EXIST instead of lingering forever. */
static void test_moqtrun_repath_fresh_own_upstream_other(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_announce(MRP_E);
  mrp_end(MRP_GA);
  mups_sub(SESS_B, MRDV_S2);
  CHECK(mrdv_is(SESS_B, MRDV_S2, ""));
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  CHECK(mrdv_is(SESS_B, MRDV_S2, "E10|FIN|"));
}

/* A's session is being closed by the hub (a malformed GOAWAY) while the
 * hub's SUBSCRIBE to A is pending: a new SUBSCRIBE does not ride it -- it
 * is DOES_NOT_EXIST at once, not held until the close lands. */
static void test_moqtrun_repath_fresh_closing_upstream(void) {
  static const u8 bad[] = {0x05};
  mups_init();
  mtst_join(SESS_C);
  mtst_join(MRP_E);
  mups_sub(SESS_C, MRDV_S1);
  CHECK(mups_up_sid() >= 0);
  mtrq_raw(SESS_A, mtdr_ctl(SESS_A), MOQCTL_T_GOAWAY, bad, sizeof bad);
  mups_sub(MRP_E, MRDV_S1);
  CHECK(mrdv_is(MRP_E, MRDV_S1, "E10|FIN|"));
}

/* A new SUBSCRIBE finding only the publisher that just ended is
 * DOES_NOT_EXIST at once. */
static void test_moqtrun_repath_fresh_dne(void) {
  mrp_init();
  mrp_end(MRP_GA);
  mups_sub(MRP_E, MRDV_S1);
  CHECK(mrdv_is(MRP_E, MRDV_S1, "E10|FIN|"));
  CHECK(mups_n_up(SESS_A) == 1);
}

/* No room to wait (C holds its share of the table): C gets the end's
 * PUBLISH_DONE at once, D waits. */
static void test_moqtrun_repath_no_room(void) {
  moqctl_ftn f = mtst_ftn("other", "room9", "x");
  u64        st;
  mrp_init();
  for (u64 i = 0; i < WIRED_MOQTRUN_RDV_PER_SESSION; i++) {
    mrdv_hold_f(SESS_C, 12 + 4 * i, &f, 1000);
  }
  mrp_end(MRP_GA);
  CHECK(mrp_dones(SESS_C, &st) == 1 && st == MOQCTL_DONE_GOING_AWAY);
  CHECK(mrp_dones(SESS_D, &st) == 0);
}

/* PUBLISH_DONEs on s's request stream sid. */
static usz mrp_dones_on(wired_wt_session* s, u64 sid) {
  usz n = 0;
  u64 count;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    if (c->s != s || c->stream_id != sid) {
      continue;
    }
    if (c->kind != 3 && c->kind != 12) {
      continue;
    }
    n += mtdr_done_in(c, &count) != ~(u64)0;
  }
  return n;
}

/* C SUBSCRIBEs ns/name on request stream sid; the hub's SUBSCRIBE for it
 * goes to s, which answers it under alias. */
static void mrp_sub_ok(
    wired_wt_session* s,
    const char*       ns2,
    const char*       name,
    u64               sid,
    u64               alias) {
  static moqctl_subscribe_ok ok;
  moqctl_ftn                 f = mtst_ftn("chat", ns2, name);
  usz                        n = mups_n_up(s);
  mtst_subscribe_p(SESS_C, sid, &f, mtst_rid += 4, 0);
  ok.track_alias = alias;
  mtst_send(s, (u64)mrp_up(s, n), MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
}

/* Re-path waits count against their session's share too: C waits for
 * WIRED_MOQTRUN_RDV_PER_SESSION Tracks of A's; its subscription to E's
 * Track, ending next, gets the end's PUBLISH_DONE at once. */
static void test_moqtrun_repath_session_share(void) {
  static moqctl_publish_done d;
  static const char* const   names[] = {"t0", "t1", "t2", "t3"};
  mups_init();
  mtst_join(SESS_C);
  mtst_join(MRP_E);
  mtns_pub(MRP_E, MRDV_S1, "chat/room2");
  for (usz i = 0; i < WIRED_MOQTRUN_RDV_PER_SESSION; i++) {
    mrp_sub_ok(SESS_A, "room1", names[i], MTRQ_ID(10 + i), 7 + i);
  }
  mrp_sub_ok(MRP_E, "room2", "x", MTRQ_ID(20), 7);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mrdv_used() == WIRED_MOQTRUN_RDV_PER_SESSION);
  d.status_code = MOQCTL_DONE_GOING_AWAY;
  mtst_send(
      MRP_E, (u64)mrp_up(MRP_E, 0), MOQCTL_T_PUBLISH_DONE, mups_enc_done, &d);
  CHECK(mrp_dones_on(SESS_C, MTRQ_ID(20)) == 1);
  for (usz i = 0; i < WIRED_MOQTRUN_RDV_PER_SESSION; i++) {
    CHECK(mrp_dones_on(SESS_C, MTRQ_ID(10 + i)) == 0);
  }
  CHECK(mrdv_used() == WIRED_MOQTRUN_RDV_PER_SESSION);
}

/* Waits are per subscription in the hub-wide rendezvous table: with one
 * more subscriber than WIRED_MOQTRUN_MAX_RDV, the last one gets the end's
 * PUBLISH_DONE at once, and a new rendezvous hold is refused
 * EXCESSIVE_LOAD while the others wait. */
static void test_moqtrun_repath_table_full(void) {
  moqctl_ftn f     = mtst_ftn("other", "room9", "x");
  usz        dones = 0;
  u64        st;
  mups_init();
  for (usz i = 0; i <= WIRED_MOQTRUN_MAX_RDV; i++) {
    mtst_join((wired_wt_session*)(40 + i));
    mups_sub((wired_wt_session*)(40 + i), MRDV_S1);
    if (!i) {
      mrp_up_a = (u64)mups_up_sid();
    }
    if (!i) {
      mups_ok(mrp_up_a);
    }
  }
  mrp_end(MRP_GA);
  for (usz i = 0; i <= WIRED_MOQTRUN_MAX_RDV; i++) {
    if (mrp_dones((wired_wt_session*)(40 + i), &st) == 1 &&
        st == MOQCTL_DONE_GOING_AWAY) {
      dones++;
    }
  }
  CHECK(dones == 1);
  CHECK(mrp_dones((wired_wt_session*)(40 + WIRED_MOQTRUN_MAX_RDV), &st) == 1);
  CHECK(mrdv_used() == WIRED_MOQTRUN_MAX_RDV);
  mrdv_hold_f(SESS_B, MRDV_S2, &f, 1000);
  CHECK(mrdv_is(SESS_B, MRDV_S2, "E9|FIN|"));
}

/* REQUEST_UPDATE while waiting is applied and answered REQUEST_OK, and
 * the re-attached subscription follows it. */
static void test_moqtrun_repath_update(void) {
  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  mrp_init();
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  mtup_update(SESS_C, MRDV_S1, &p0);
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|ROK|"));
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  mrp_group(SESS_B, MUPS_DATA_SID, 0, MOQDATA_STATUS_NORMAL);
  CHECK(mups_relayed_alias(SESS_C) == ~(u64)0);
  CHECK(mups_relayed_alias(SESS_D) == mrdv_alias(SESS_D, MRDV_S1));
}

/* C's own announcement is no path for C, but is one for D: C, which
 * cannot be re-attached to its own track, gets its PUBLISH_DONE then. */
static void test_moqtrun_repath_own_announce(void) {
  u64 st;
  mrp_init();
  mtns_pub(SESS_C, MRDV_S2, "chat/room1");
  mrp_end(MRP_GA);
  CHECK(mups_n_up(SESS_C) == 1);
  CHECK(mrp_no_done());
  mrp_ok(SESS_C, mrp_up(SESS_C, 0));
  CHECK(mrp_dones(SESS_C, &st) == 1 && st == MOQCTL_DONE_GOING_AWAY);
  CHECK(mrp_dones(SESS_D, &st) == 0);
  mrp_group(SESS_C, MUPS_DATA_SID, 0, MOQDATA_STATUS_NORMAL);
  CHECK(mups_relayed_alias(SESS_D) == mrdv_alias(SESS_D, MRDV_S1));
}

/* C's own announcement (made before B's) is a path for D only, B's for
 * both: B is asked first, even by D's wait (D subscribed before C, so it
 * looks first), and its SUBSCRIBE_OK re-attaches C and D. */
static void test_moqtrun_repath_prefers_outsider(void) {
  mups_init();
  mtst_join(SESS_C);
  mtst_join(SESS_D);
  mups_sub(SESS_D, MRDV_S1);
  mups_sub(SESS_C, MRDV_S1);
  mrp_up_a = (u64)mups_up_sid();
  mups_ok(mrp_up_a);
  mtns_pub(SESS_C, MRDV_S2, "chat/room1");
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  CHECK(mups_n_up(SESS_C) == 0);
  CHECK(mups_n_up(SESS_B) == 1);
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  CHECK(mrp_relayed(SESS_B));
  CHECK(mrp_no_done());
}

/* C's remembered subscriptions wrap while it waits (as many SUBSCRIBEs
 * to another Track, each cancelled): C can no longer be re-attached, so
 * B's SUBSCRIBE_OK ends C's wait with its PUBLISH_DONE; D is re-attached. */
static void test_moqtrun_repath_names_wrapped(void) {
  moqctl_ftn x = mtst_ftn("chat", "room2", "bob");
  u64        st;
  mrp_init();
  mtst_publish(MRP_E, MTRQ_ID(1), &x, 3);
  mrp_announce(SESS_B);
  mrp_end(MRP_GA);
  for (usz i = 0; i < WIRED_MOQTRUN_SUB_NAMES; i++) {
    mtst_subscribe_p(SESS_C, MTRQ_ID(10 + i), &x, mtst_rid += 4, 0);
    wired_moqt_on_stream_reset(&mtst_hub, SESS_C, MTRQ_ID(10 + i), 0, 0);
  }
  mrp_ok(SESS_B, mrp_up(SESS_B, 0));
  CHECK(mrp_dones(SESS_C, &st) == 1 && st == MOQCTL_DONE_GOING_AWAY);
  CHECK(mrp_dones(SESS_D, &st) == 0);
  CHECK(mrdv_used() == 0);
}

/* A Malformed Track ends at once; B is not asked. */
static void test_moqtrun_repath_malformed(void) {
  mrp_init();
  mrp_announce(SESS_B);
  mrp_group(SESS_A, MUPS_DATA_SID, 1, MOQDATA_STATUS_END_OF_TRACK);
  mrp_group(SESS_A, MUPS_DATA_SID + 4, 2, MOQDATA_STATUS_NORMAL);
  CHECK(mrp_done_once_n(MOQCTL_DONE_MALFORMED_TRACK, 2));
  CHECK(mups_n_up(SESS_B) == 0);
}

static void mtall_repath(void) {
  test_moqtrun_repath_takeover();
  test_moqtrun_repath_each_end();
  test_moqtrun_repath_hub_closes();
  test_moqtrun_repath_final_status();
  test_moqtrun_repath_silent_wait();
  test_moqtrun_repath_late_announce();
  test_moqtrun_repath_expiry();
  test_moqtrun_repath_expiry_status();
  test_moqtrun_repath_deadline_beats_pending();
  test_moqtrun_repath_deadline_fixed();
  test_moqtrun_repath_refusal_hidden();
  test_moqtrun_repath_failover();
  test_moqtrun_repath_ender_skipped();
  test_moqtrun_repath_untry_covering();
  test_moqtrun_repath_leave();
  test_moqtrun_repath_all_leave();
  test_moqtrun_repath_withdraw_keeps();
  test_moqtrun_repath_new_closes();
  test_moqtrun_repath_one_upstream();
  test_moqtrun_repath_stale_ok();
  test_moqtrun_repath_ends_again();
  test_moqtrun_repath_done_once();
  test_moqtrun_repath_stream_count();
  test_moqtrun_repath_done_fields_set_at_claim();
  test_moqtrun_repath_drain_flush();
  test_moqtrun_repath_fresh_rides();
  test_moqtrun_repath_fresh_dne();
  test_moqtrun_repath_fresh_own_upstream();
  test_moqtrun_repath_fresh_own_upstream_other();
  test_moqtrun_repath_fresh_own_upstream_rt();
  test_moqtrun_repath_fresh_closing_upstream();
  test_moqtrun_repath_no_room();
  test_moqtrun_repath_table_full();
  test_moqtrun_repath_session_share();
  test_moqtrun_repath_update();
  test_moqtrun_repath_own_announce();
  test_moqtrun_repath_prefers_outsider();
  test_moqtrun_repath_names_wrapped();
  test_moqtrun_repath_malformed();
}

void test_moqtrun_repath(void) { moqtrun_test_allver(mtall_repath); }
