/* Upstream SUBSCRIBE (ledger 12-3): a SUBSCRIBE missing every PUBLISHed
 * track whose namespace a session announced with PUBLISH_NAMESPACE is
 * sent upstream to that publisher, and answered SUBSCRIBE_OK only once
 * the upstream subscription is Established (draft-ietf-moq-transport-
 * 18/19 9.4-9.5, draft-22 7.4/7.6). One upstream subscription serves every
 * downstream subscriber of the Track. Shares the recording io stubs
 * (moqtrun_test.c) and the fixtures of moqtrun_sub_test.c, moqtrun_ns_test.c,
 * moqtrun_subtracks_test.c and moqtrun_rdv_test.c (same unity TU). */

#define MUPS_ALIAS 7
#define MUPS_DATA_SID 1001

/* The hub's next opened stream gets a server-initiated bidi id (1 mod 4,
 * RFC 9000 2.1), as in production -- a stale reply on it is then never
 * mistaken for a client request stream (moqtrun_req_stream_ok). */
static void mups_sids(void) { g_next_stream_id = 201; }

/* A announces chat/room1 on its request stream MRDV_S1. */
static void mups_announce(void) { mtns_pub(SESS_A, MRDV_S1, "chat/room1"); }

/* A, B joined at clock 0 under the drafts pv / sv; A announced. */
static void mups_init_v(int pv, int sv) {
  mrdv_init();
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = pv;
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = sv;
  mups_announce();
  mups_sids();
}

static void mups_init(void) {
  mups_init_v(g_moqtrun_test_ver, g_moqtrun_test_ver);
}

/* s SUBSCRIBEs the awaited track, no RENDEZVOUS_TIMEOUT. */
static void mups_sub(wired_wt_session* s, u64 sid) {
  moqctl_ftn f = mrdv_f();
  mtst_subscribe_p(s, sid, &f, mtst_rid += 4, 0);
}

/* The which-th SUBSCRIBE the hub opened toward s (decoded in s's draft
 * into *m, its stream id returned); -1 if there is none. */
static i64 mups_up(wired_wt_session* s, usz which, moqctl_subscribe* m) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0, boff = 0;
    u64                      type;
    wired_span               body;
    if (c->kind != 1 || c->s != s) {
      continue;
    }
    mt_peek_type(wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type != MOQCTL_T_SUBSCRIBE) {
      continue;
    }
    if (n++ != which) {
      continue;
    }
    CHECK(moqctl_subscribe_take(mtst_ver(s), body, &boff, m) == MOQCTL_OK);
    return (i64)c->stream_id;
  }
  return -1;
}

/* Upstream SUBSCRIBEs opened toward s. */
static usz mups_n_up(wired_wt_session* s) {
  moqctl_subscribe m;
  usz              n = 0;
  while (mups_up(s, n, &m) >= 0) {
    n++;
  }
  return n;
}

static i64 mups_up_sid(void) {
  moqctl_subscribe m;
  return mups_up(SESS_A, 0, &m);
}

static int mups_enc_ok(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_ok_encode(buf, off, m);
}

static int mups_enc_done(wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_done_encode(buf, off, m);
}

/* A answers SUBSCRIBE_OK (Track Alias MUPS_ALIAS) on its stream sid. */
static void mups_ok(u64 sid) {
  static moqctl_subscribe_ok ok;
  ok.track_alias = MUPS_ALIAS;
  mtst_send(SESS_A, sid, MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
}

static void mups_done(u64 sid, u64 status) {
  static moqctl_publish_done d;
  d.status_code  = status;
  d.stream_count = 0;
  mtst_send(SESS_A, sid, MOQCTL_T_PUBLISH_DONE, mups_enc_done, &d);
}

/* Upstream entries in use. */
static usz mups_used(void) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    n += mtst_hub.ups[i].in_use != 0;
  }
  return n;
}

/* Hub ops on A's upstream stream sid: "RST<code>|", "STOP<code>|",
 * "FIN|", in order. */
static const char* mups_up_log(u64 sid) {
  mrdv_at = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    if (c->s != SESS_A || c->stream_id != sid) {
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

static int mups_up_is(u64 sid, const char* want) {
  const char* got = mups_up_log(sid);
  usz         i   = 0;
  while (got[i] && got[i] == want[i]) {
    i++;
  }
  if (got[i] != want[i]) {
    printf("  up got \"%s\" want \"%s\"\n", got, want);
  }
  return got[i] == want[i];
}

/* 9.4/7.4: B's SUBSCRIBE goes upstream as a
 * SUBSCRIBE in A's draft with the server's odd Request ID (10.1) and no
 * parameters (FORWARD defaults to 1, unfiltered); B hears nothing until
 * A's SUBSCRIBE_OK, then SUBSCRIBE_OK, and B is an active subscriber of
 * the track A's alias now names. */
static void test_moqtrun_upsub_ok_after_upstream(void) {
  moqctl_subscribe m;
  moqctl_ftn       f = mrdv_f();
  i64              sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  sid = mups_up(SESS_A, 0, &m);
  CHECK(sid >= 0);
  CHECK((m.request_id & 1) == 1);
  CHECK(m.params.n == 0);
  CHECK(m.name.name.n == f.name.n);
  CHECK(m.name.ns.n == 2);
  mups_ok((u64)sid);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  CHECK(mrdv_alias(SESS_B, MRDV_S1) == mtst_sub(SESS_A, SESS_B)->track_alias);
  CHECK(mrdv_used() == 0);
  CHECK(mups_used() == 1);
}

/* Header (Type 0x30, alias, Group 0) + one Object. */
static usz mups_stream(u64 alias, u8* buf) {
  moqdata_subhdr h   = {0};
  usz            off = 0;
  u8             b   = 0x5a;
  wired_mspan    out = wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD);
  h.type             = 0x30;
  h.track_alias      = alias;
  moqdata_subhdr_put(out, &off, &h);
  moqdata_obj_put(out, &off, 0, wired_span_of(&b, 1));
  return off;
}

/* Track Alias of the last uni stream the hub sent s; ~0 if none. */
static u64 mups_relayed_alias(wired_wt_session* s) {
  u64 alias = ~(u64)0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0;
    moqdata_subhdr           h;
    if (c->s != s || (c->kind != 4 && c->kind != 5)) {
      continue;
    }
    if (moqdata_subhdr_take(
            wired_span_of(c->payload, c->payload_len), &off, &h) ==
        MOQDATA_OK) {
      alias = h.track_alias;
    }
  }
  return alias;
}

/* 9.4 ("Relays use the Track Alias of an incoming Object"): A's
 * SUBGROUP stream under the alias its SUBSCRIBE_OK named reaches B under
 * B's own alias (moqtrun_alias_splice). */
static void test_moqtrun_upsub_objects_relayed(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mups_ok((u64)mups_up_sid());
  n = mups_stream(MUPS_ALIAS, buf);
  mt_feed(&mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(buf, n), 1);
  CHECK(mups_relayed_alias(SESS_B) == mrdv_alias(SESS_B, MRDV_S1));
}

/* d22 3.1.3.1 MAY: a SUBGROUP stream that beats the publisher's own
 * SUBSCRIBE_OK (its Track Alias still unknown) is held and relayed once
 * the OK claims the track. */
static void test_moqtrun_upsub_stream_before_ok(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  n = mups_stream(MUPS_ALIAS, buf);
  mt_feed(&mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(buf, n), 1);
  CHECK(mups_relayed_alias(SESS_B) == ~(u64)0);
  mups_ok((u64)mups_up_sid());
  CHECK(mups_relayed_alias(SESS_B) == mrdv_alias(SESS_B, MRDV_S1));
}

/* The same for a keep-open stream: its later deliveries before the OK
 * follow it into the hold, the ones after go on as a relay. */
static void test_moqtrun_upsub_open_stream_before_ok(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  n = mups_stream(MUPS_ALIAS, buf);
  mt_feed(&mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(buf, n), 0);
  mups_ok((u64)mups_up_sid());
  CHECK(mups_relayed_alias(SESS_B) == mrdv_alias(SESS_B, MRDV_S1));
  const moqtrun_test_call* o = moqtrun_test_last_kind(5);
  CHECK(o && o->s == SESS_B);
  u64 relay_sid = o ? o->stream_id : 0;
  moqtrun_test_reset();
  mt_feed(&mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(0, 0), 1);
  const moqtrun_test_call* f = moqtrun_test_last_kind(6);
  CHECK(f && f->s == SESS_B && f->stream_id == relay_sid);
}

/* A's SUBSCRIBE_OK arrives while A already publishes as many tracks as a
 * session's slots hold: the hub cannot take the track, so the upstream
 * subscription is cancelled and B refused EXCESSIVE_LOAD (draft-22 9.4
 * relays MAY refuse under load) -- never left waiting. */
static void test_moqtrun_upsub_ok_no_track_slot(void) {
  static const char* const names[] = {"p0", "p1", "p2", "p3", "p4"};
  mups_init();
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; i++) {
    moqctl_ftn f = mtst_ftn("chat", "room1", names[i]);
    mtst_publish(SESS_A, MTRQ_ID(i), &f, 20 + i);
  }
  mups_sub(SESS_B, MRDV_S1);
  u64 sid = (u64)mups_up_sid();
  mups_ok(sid);
  CHECK(mrdv_err(SESS_B, MRDV_S1).error_code == MOQCTL_ERR_EXCESSIVE_LOAD);
  CHECK(mups_used() == 0);
}

/* A keep-open stream held before the OK that the publisher then resets
 * (RFC 9000 19.4) is gone: nothing of it is relayed once the OK comes. */
static void test_moqtrun_upsub_early_stream_reset(void) {
  u8 buf[MOQTRUN_TEST_MAX_PAYLOAD];
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mt_feed(
      &mtst_hub, SESS_A, MUPS_DATA_SID,
      wired_span_of(buf, mups_stream(MUPS_ALIAS, buf)), 0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MUPS_DATA_SID, 0, 0);
  mups_ok((u64)mups_up_sid());
  CHECK(mups_relayed_alias(SESS_B) == ~(u64)0);
}

/* The held stream is bounded (WIRED_MOQTRUN_EARLY_BUF): a later delivery
 * that does not fit drops the whole stream rather than relaying a torn
 * one. */
static void test_moqtrun_upsub_early_stream_overflow(void) {
  static u8 more[WIRED_MOQTRUN_EARLY_BUF];
  u8        buf[MOQTRUN_TEST_MAX_PAYLOAD];
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mt_feed(
      &mtst_hub, SESS_A, MUPS_DATA_SID,
      wired_span_of(buf, mups_stream(MUPS_ALIAS, buf)), 0);
  mt_feed(
      &mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(more, sizeof more), 0);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A)->early_n == 0);
  mups_ok((u64)mups_up_sid());
  CHECK(mups_relayed_alias(SESS_B) == ~(u64)0);
}

/* A stream that ends (FIN) inside its SUBGROUP_HEADER names no track and
 * is not held for the pending OK (draft-22 11.4.2: no stream at all). */
static void test_moqtrun_upsub_early_torn_header(void) {
  static const u8 torn[] = {0x30, MUPS_ALIAS};
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mt_feed(&mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(torn, 2), 1);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A)->early_n == 0);
  CHECK(moqtrun_test_count_kind(11) == 0);
}

/* Aggregation (9.4 MAY): B and C waiting share one upstream SUBSCRIBE
 * and both get SUBSCRIBE_OK; D arriving once it is Established is
 * answered at once, still with one upstream. */
static void test_moqtrun_upsub_two_share_one(void) {
  mups_init();
  mtst_join(SESS_C);
  mtst_join(SESS_D);
  mups_sub(SESS_B, MRDV_S1);
  mups_sub(SESS_C, MRDV_S1);
  CHECK(mups_n_up(SESS_A) == 1);
  mups_ok((u64)mups_up_sid());
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
  mups_sub(SESS_D, MRDV_S1);
  CHECK(mrdv_is(SESS_D, MRDV_S1, "SOK|"));
  CHECK(mups_n_up(SESS_A) == 1);
}

/* 9.4: A's REQUEST_ERROR reaches every waiter with its code; the
 * hub ends its side of the upstream stream and forgets the entry. */
static void test_moqtrun_upsub_error_relayed(void) {
  u64 sid;
  mups_init();
  mtst_join(SESS_C);
  mups_sub(SESS_B, MRDV_S1);
  mups_sub(SESS_C, MRDV_S1);
  sid = (u64)mups_up_sid();
  mtst_pub_err(SESS_A, sid, MOQCTL_ERR_UNAUTHORIZED);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E1|FIN|"));
  CHECK(mrdv_is(SESS_C, MRDV_S1, "E1|FIN|"));
  CHECK(mups_up_is(sid, "FIN|"));
  CHECK(mups_used() == 0);
  CHECK(mrdv_used() == 0);
}

/* draft-19 3.3.2: A FINs its side with no SUBSCRIBE_OK -- the request
 * failed: B is refused as for a REQUEST_ERROR and the hub FINs and
 * forgets the entry. A FIN after SUBSCRIBE_OK ends nothing. */
static void test_moqtrun_upsub_fin_unanswered_fails(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mt_feed(&mtst_hub, SESS_A, sid, wired_span_of(0, 0), 1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E0|FIN|"));
  CHECK(mups_up_is(sid, "FIN|"));
  CHECK(mups_used() == 0);
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok(sid);
  mt_feed(&mtst_hub, SESS_A, sid, wired_span_of(0, 0), 1);
  CHECK(mups_up_is(sid, ""));
  CHECK(mups_used() == 1);
}

/* First call of kind k1 or k2 on (s, sid); ~0 if none. */
static usz mups_first(wired_wt_session* s, u64 sid, int k1, int k2) {
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    if (c->s == s && c->stream_id == sid && (c->kind == k1 || c->kind == k2)) {
      return i;
    }
  }
  return ~(usz)0;
}

/* draft-18 5.1: A PUBLISHes the Track the hub's SUBSCRIBE to A still
 * waits on (Pending, subscriber): that SUBSCRIBE is cancelled before A's
 * PUBLISH_OK goes out (MUST), and B rides A's PUBLISH. */
static void test_moqtrun_upsub_publish_crosses(void) {
  moqctl_ftn f   = mrdv_f();
  u64        pub = MTRQ_ID(5);
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  u64 sid = (u64)mups_up_sid();
  mtst_publish(SESS_A, pub, &f, 1);
  usz rst = mups_first(SESS_A, sid, 7, 7);
  usz ok  = mups_first(SESS_A, pub, 3, 12);
  CHECK(ok != ~(usz)0);
  if (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_DUP_SUBSCRIPTION) {
    CHECK(rst < ok);
  }
  CHECK(mups_used() == 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
}

/* 9.4: the upstream outlives one downstream cancel, and is
 * cancelled (RESET_STREAM + STOP_SENDING CANCELLED, 19 3.3.3) with the
 * last; A's track goes with it. */
static void test_moqtrun_upsub_last_cancel_cancels_upstream(void) {
  u64 sid;
  mups_init();
  mtst_join(SESS_C);
  mups_sub(SESS_B, MRDV_S1);
  mups_sub(SESS_C, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok(sid);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MRDV_S1, 0, 0);
  CHECK(mups_up_is(sid, ""));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_C, MRDV_S1, 0, 0);
  CHECK(mups_up_is(sid, "RST1|STOP1|"));
  CHECK(mups_used() == 0);
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use);
}

/* 9.4, pending, and a stale reply: the only waiter cancels before the
 * answer -- the upstream is cancelled, and A's late SUBSCRIBE_OK on that
 * stream claims nothing and answers no one. */
static void test_moqtrun_upsub_pending_cancel_and_stale_ok(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MRDV_S1, 0, 0);
  CHECK(mups_up_is(sid, "RST1|STOP1|"));
  CHECK(mups_used() == 0);
  mups_ok(sid);
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use);
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->closing);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "RST1|"));
}

/* draft-23 12.3 TIMEOUT ("a relay could not establish an upstream
 * subscription within the timeout"): A stays alive and never answers;
 * after WIRED_MOQTRUN_UP_WAIT_MS B is refused TIMEOUT, and the upstream
 * SUBSCRIBE nobody waits for any more is cancelled. */
static void test_moqtrun_upsub_silent_upstream_times_out(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_UP_WAIT_MS - 1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_UP_WAIT_MS);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E2|FIN|"));
  CHECK(mups_up_is(sid, "RST1|STOP1|"));
  CHECK(mups_used() == 0 && mrdv_used() == 0);
}

/* 10.11, relayed: A's PUBLISH_DONE on the upstream stream reaches B
 * as PUBLISH_DONE on B's stream; the hub then ends its upstream side. */
static void test_moqtrun_upsub_publish_done_relayed(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok(sid);
  mups_done(sid, MOQCTL_DONE_TRACK_ENDED);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|Tb|FIN|"));
  CHECK(mups_up_is(sid, "FIN|"));
  CHECK(mups_used() == 0);
}

/* 9.4: A's session closing frees its entries with no io; a
 * waiter left with no announcer gets DOES_NOT_EXIST (INTERNAL_ERROR for
 * the lost upstream on draft-23), an Established
 * subscriber waits for another announcer and, with none, gets its
 * PUBLISH_DONE at the end of that wait (moqtrun_repath_test.c). */
static void test_moqtrun_upsub_publisher_close(void) {
  int lost = (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_UP_LOSS) != 0;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mrdv_is(SESS_B, MRDV_S1, lost ? "E0|FIN|" : "E10|FIN|"));
  CHECK(mups_used() == 0);
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mups_ok((u64)mups_up_sid());
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|Tb|FIN|"));
  CHECK(mups_used() == 0);
}

/* d22 6.4.2.3: A resets the hub's upstream SUBSCRIBE stream -- the
 * request is cancelled. A waiter is refused INTERNAL_ERROR, an
 * Established subscriber waits for another announcer and, with none,
 * gets its PUBLISH_DONE at the end of that wait; the hub resets its own
 * side and frees the entry. */
static void test_moqtrun_upsub_publisher_reset(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, sid, 1, 0);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E0|FIN|"));
  CHECK(mups_up_is(sid, "RST1|"));
  CHECK(mups_used() == 0);
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok(sid);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, sid, 1, 0);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|Tb|FIN|"));
  CHECK(mups_up_is(sid, "RST1|"));
  CHECK(mups_used() == 0);
}

/* 9.5 ("a PUBLISH_NAMESPACE ... MUST send a SUBSCRIBE"; interop
 * subscribe-before-announce): a rendezvous hold made before any
 * announcer goes upstream once A announces, and resolves on its OK. */
static void test_moqtrun_upsub_hold_then_announce(void) {
  mrdv_init();
  mups_sids();
  mrdv_hold(SESS_B, MRDV_S1, 500);
  CHECK(mups_n_up(SESS_A) == 0);
  mups_announce();
  CHECK(mups_n_up(SESS_A) == 1);
  mups_ok((u64)mups_up_sid());
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  wired_moqt_tick(&mtst_hub, 600);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
}

/* No stream to open toward the publisher (the QUIC stream limit is
 * MOQT's request limit since draft-18 removed MAX_REQUEST_ID) -- the
 * SUBSCRIBE is refused now, nothing is held: EXCESSIVE_LOAD without a
 * Retry Interval before draft-23, UNAVAILABLE with one in draft-23 7.4. */
static void test_moqtrun_upsub_open_fails(void) {
  int d23 = (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_UNAVAILABLE) != 0;
  mups_init();
  g_open_bidi_fail_n = 1;
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, d23 ? "Ea|FIN|" : "E9|FIN|"));
  CHECK(
      mrdv_err(SESS_B, MRDV_S1).retry_interval ==
      (d23 ? WIRED_MOQTRUN_RDV_RETRY : 0));
  CHECK(mups_used() == 0);
  CHECK(mrdv_used() == 0);
}

/* A session's own announcement never routes its SUBSCRIBE back to
 * itself; with no other announcer it is DOES_NOT_EXIST at once. */
static void test_moqtrun_upsub_own_namespace(void) {
  mrdv_init();
  mtns_pub(SESS_B, MRDV_S2, "chat/room1");
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E10|FIN|"));
  CHECK(mups_n_up(SESS_B) == 0);
}

/* Prefix matching (9.5): an announcement of the namespace's first
 * field alone covers it; an unrelated one does not. */
static void test_moqtrun_upsub_prefix(void) {
  mrdv_init();
  mtns_pub(SESS_A, MRDV_S1, "other");
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "E10|FIN|"));
  mtns_pub(SESS_A, MRDV_S2, "chat");
  mups_sub(SESS_B, MRDV_S2);
  CHECK(mups_n_up(SESS_A) == 1);
}

/* A answers SUBSCRIBE_OK on sid with one Track Property (type, num). */
static void mups_ok_prop(u64 sid, u64 type, u64 num) {
  static moqctl_subscribe_ok ok;
  static u8                  props[16];
  usz                        n    = 0;
  u64                        prev = 0;
  moqkvp                     kv   = {0};
  kv.type                         = type;
  kv.num                          = num;
  CHECK(moqkvp_put(wired_mspan_of(props, sizeof props), &n, &prev, &kv));
  ok.track_alias      = MUPS_ALIAS;
  ok.track_properties = wired_span_of(props, n);
  mtst_send(SESS_A, sid, MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
}

/* ===== NEW_GROUP_REQUEST relayed upstream (draft-18 10.2.13) ===== */

static moqctl_params mups_ngr(u64 v) {
  moqctl_params p = {0};
  moqtrun_ngr_add(&p, v);
  return p;
}

/* s SUBSCRIBEs the awaited track on sid with NEW_GROUP_REQUEST v. */
static void mups_sub_ngr(wired_wt_session* s, u64 sid, u64 v) {
  moqctl_ftn    f = mrdv_f();
  moqctl_params p = mups_ngr(v);
  mtst_subscribe_p(s, sid, &f, mtst_rid += 2, &p);
}

/* REQUEST_UPDATEs the hub sent A on sid; the last one's
 * NEW_GROUP_REQUEST in *v (~0 when it has none). */
static usz mups_ngr_sent(u64 sid, u64* v) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0;
    u64                      type;
    wired_span               body;
    moqtstat_update          m;
    if (c->s != SESS_A || c->stream_id != sid || c->kind != 3) {
      continue;
    }
    mt_peek_type(wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type != MOQTSTAT_T_REQUEST_UPDATE) {
      continue;
    }
    CHECK(
        moqtstat_update_take(
            mtst_ver(SESS_A), body, MOQCTL_PCTX_UPDATE_SUBSCRIPTION, &m) ==
        MOQCTL_OK);
    CHECK((m.request_id & 1) == 1);
    const moqctl_param* g =
        moqctl_params_find(&m.params, MOQCTL_PARAM_NEW_GROUP_REQUEST);
    *v = g ? g->vi : ~(u64)0;
    n++;
  }
  return n;
}

/* No Established subscription yet: B's NEW_GROUP_REQUEST rides the
 * hub's upstream SUBSCRIBE (MUST). */
static void test_moqtrun_upsub_ngr_in_subscribe(void) {
  moqctl_subscribe m;
  mups_init();
  mups_sub_ngr(SESS_B, MRDV_S1, 5);
  CHECK(mups_up(SESS_A, 0, &m) >= 0);
  const moqctl_param* g =
      moqctl_params_find(&m.params, MOQCTL_PARAM_NEW_GROUP_REQUEST);
  CHECK(g != 0 && g->vi == 5);
}

/* Established through the hub's SUBSCRIBE, Largest Group 0 (one Object):
 * C's NEW_GROUP_REQUEST v goes to A in a REQUEST_UPDATE when dyn and v is
 * 0 or above the Largest Group; want is how many went out. */
static void mups_ngr_established(int dyn, u64 v, usz want) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u64 got = 0;
  mups_init();
  mtst_join(SESS_C);
  mups_sub(SESS_B, MRDV_S1);
  u64 sid = (u64)mups_up_sid();
  mups_ok_prop(sid, MOQTRUN_PROP_DYNAMIC_GROUPS, (u64)dyn);
  usz n = mups_stream(MUPS_ALIAS, buf);
  mt_feed(&mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(buf, n), 1);
  mups_sub_ngr(SESS_C, MRDV_S1, v);
  CHECK(mups_ngr_sent(sid, &got) == want);
  CHECK(!want || got == v);
}

/* A second request of no greater value is held back while the first is
 * outstanding; once the Largest Group moves, a REQUEST_UPDATE's request
 * goes out again. */
static void test_moqtrun_upsub_ngr_update(void) {
  u8            buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u64           got = 0;
  moqctl_params p0  = mups_ngr(0);
  mups_ngr_established(1, 0, 1);
  mups_ngr_established(1, 1, 1); /* above Largest Group 0 */
  mups_ngr_established(0, 0, 0); /* no dynamic Groups */
  mups_init();
  mtst_join(SESS_C);
  mtst_join(SESS_D);
  mups_sub(SESS_B, MRDV_S1);
  u64 sid = (u64)mups_up_sid();
  mups_ok_prop(sid, MOQTRUN_PROP_DYNAMIC_GROUPS, 1);
  mups_sub_ngr(SESS_C, MRDV_S1, 3);
  mups_sub_ngr(SESS_D, MRDV_S1, 2);
  CHECK(mups_ngr_sent(sid, &got) == 1 && got == 3);
  usz n = mups_stream(MUPS_ALIAS, buf);
  mt_feed(&mtst_hub, SESS_A, MUPS_DATA_SID, wired_span_of(buf, n), 1);
  mtup_update(SESS_D, MRDV_S1, &p0);
  CHECK(mups_ngr_sent(sid, &got) == 2 && got == 0);
}

/* draft-18 12.5 / 12.6: an upstream SUBSCRIBE_OK's out-of-range
 * DEFAULT_PUBLISHER_GROUP_ORDER closes A's session PROTOCOL_VIOLATION;
 * no track is claimed. */
static void test_moqtrun_upsub_ok_bad_prop_closes(void) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mups_ok_prop((u64)mups_up_sid(), 0x22, 3);
  CHECK(mtrq_closes_cc(WIRED_MOQTRUN_CLOSE_MALFORMED_KEY_VALUE) == 1);
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use);
}

/* draft-19 2.5.1 (draft-18 2.5.1, draft-22 3.7): an upstream SUBSCRIBE_OK
 * with a Mandatory Track Property (0x4000-0x7FFF) the hub does not
 * understand: "the subscriber MUST cancel the subscription ... it MUST
 * send REQUEST_ERROR with error code UNSUPPORTED_EXTENSION to the
 * downstream subscribers". */
static void test_moqtrun_upsub_ok_mandatory_refused(void) {
  u64 sid;
  mups_init();
  mtst_join(SESS_C);
  mups_sub(SESS_B, MRDV_S1);
  mups_sub(SESS_C, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok_prop(sid, 0x4000, 1);
  CHECK(
      mtrq_err_on(MRDV_S1) ==
      moqctl_request_error_for(
          g_moqtrun_test_ver, MOQCTL_ERR_UNSUPPORTED_EXTENSION));
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use);
  CHECK(mups_up_is(sid, "RST1|STOP1|"));
  CHECK(mups_used() == 0);
  CHECK(mtrq_closes() == 0);
}

/* Calls the hub made toward s from call index from on. */
static usz mups_calls_to(wired_wt_session* s, usz from) {
  usz n = 0;
  for (usz i = from; i < g_n_calls; i++) {
    n += g_calls[i].s == s;
  }
  return n;
}

/* draft-23 6.6: once the hub closed B's session, the other peers going
 * on queue nothing for B -- A answers the upstream SUBSCRIBE B and C wait
 * on and sends Objects, D announces a namespace B's SUBSCRIBE_NAMESPACE
 * matches, time passes -- while C is still served. */
static void test_moqtrun_upsub_closed_session_gets_nothing(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz before;
  mups_init();
  mtst_join(SESS_C);
  mtst_join(SESS_D);
  mtns_sub(SESS_B, MRDV_S2, "chat");
  mups_sub(SESS_B, MRDV_S1);
  mups_sub(SESS_C, MRDV_S1);
  CHECK(moqtrun_peer_close(
      &mtst_hub, moqtrun_find_by_wt(&mtst_hub, SESS_B), 0x3));
  before = g_n_calls;
  mups_ok((u64)mups_up_sid());
  mt_feed(
      &mtst_hub, SESS_A, MUPS_DATA_SID,
      wired_span_of(buf, mups_stream(MUPS_ALIAS, buf)), 1);
  mtns_pub(SESS_D, MRDV_S1, "chat/room9");
  wired_moqt_tick(&mtst_hub, 1000);
  CHECK(mups_calls_to(SESS_B, before) == 0);
  CHECK(mrdv_is(SESS_C, MRDV_S1, "SOK|"));
  CHECK(mups_relayed_alias(SESS_C) == mrdv_alias(SESS_C, MRDV_S1));
}

static void mtall_upsub(void) {
  test_moqtrun_upsub_closed_session_gets_nothing();
  test_moqtrun_upsub_ok_after_upstream();
  test_moqtrun_upsub_objects_relayed();
  test_moqtrun_upsub_stream_before_ok();
  test_moqtrun_upsub_open_stream_before_ok();
  test_moqtrun_upsub_early_stream_reset();
  test_moqtrun_upsub_ok_no_track_slot();
  test_moqtrun_upsub_early_stream_overflow();
  test_moqtrun_upsub_early_torn_header();
  test_moqtrun_upsub_two_share_one();
  test_moqtrun_upsub_error_relayed();
  test_moqtrun_upsub_fin_unanswered_fails();
  test_moqtrun_upsub_publish_crosses();
  test_moqtrun_upsub_ngr_in_subscribe();
  test_moqtrun_upsub_ngr_update();
  test_moqtrun_upsub_last_cancel_cancels_upstream();
  test_moqtrun_upsub_pending_cancel_and_stale_ok();
  test_moqtrun_upsub_silent_upstream_times_out();
  test_moqtrun_upsub_publish_done_relayed();
  test_moqtrun_upsub_publisher_close();
  test_moqtrun_upsub_publisher_reset();
  test_moqtrun_upsub_hold_then_announce();
  test_moqtrun_upsub_open_fails();
  test_moqtrun_upsub_own_namespace();
  test_moqtrun_upsub_prefix();
  test_moqtrun_upsub_ok_bad_prop_closes();
  test_moqtrun_upsub_ok_mandatory_refused();
}

/* Cross-draft: A's reply decoded in A's draft, B's answer spelled in B's
 * (a d19/22 CONFLICTING_FILTERS reaches a d18 subscriber as d18's
 * EXCESSIVE_LOAD, moqctl_request_error_for). */
static void mups_xver(int pv, int sv) {
  u64 sid;
  mups_init_v(pv, sv);
  mups_sub(SESS_B, MRDV_S1);
  mups_ok((u64)mups_up_sid());
  CHECK(mrdv_alias(SESS_B, MRDV_S1) == mtst_sub(SESS_A, SESS_B)->track_alias);
  mups_init_v(pv, sv);
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mtst_pub_err(SESS_A, sid, MOQCTL_ERR_CONFLICTING_FILTERS);
  CHECK(
      mrdv_err(SESS_B, MRDV_S1).error_code ==
      moqctl_request_error_for(sv, MOQCTL_ERR_CONFLICTING_FILTERS));
}

static void test_moqtrun_upsub_cross_draft(void) {
  for (int pv = 0; pv < MOQVER_COUNT; pv++) {
    for (int sv = 0; sv < MOQVER_COUNT; sv++) {
      int fails = wired_test_fails;
      mups_xver(pv, sv);
      if (wired_test_fails != fails) {
        printf("  ^ pub %d sub %d\n", pv, sv);
      }
    }
  }
}

/* draft-19 11.1 (draft-22 3.1.3): an upstream SUBSCRIBE_OK naming the
 * Track Alias of another live track of the publisher's session closes it
 * DUPLICATE_TRACK_ALIAS and claims nothing. */
static void test_moqtrun_upsub_dup_alias_closes(void) {
  moqctl_ftn g = mtst_ftn("chat", "room1", "carol");
  u64        sid;
  mups_init();
  mtst_publish(SESS_A, 44, &g, MUPS_ALIAS);
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok(sid);
  CHECK(moqtrun_test_close_code() == WIRED_MOQTRUN_CLOSE_DUPLICATE_TRACK_ALIAS);
}

/* draft-19 10.6.1 (draft-22 9.4): a REQUEST_ERROR answering the hub's
 * upstream SUBSCRIBE with a non-zero Connect URI Length closes the
 * publisher's session PROTOCOL_VIOLATION. */
static void test_moqtrun_upsub_redirect_uri_closes(void) {
  static moqctl_request_error e;
  u64                         sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid                    = (u64)mups_up_sid();
  e.error_code           = MOQCTL_ERR_REDIRECT;
  e.has_redirect         = 1;
  e.redirect.connect_uri = mtst_z("https://r.example/moq");
  mtst_send(
      SESS_A, sid, MOQCTL_T_REQUEST_ERROR, mtsub_encode_request_error, &e);
  CHECK(moqtrun_test_close_code() == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* draft-19 5.1 (draft-18 5.1, draft-22 3.1): a publisher answers a
 * SUBSCRIBE exactly once; a second SUBSCRIBE_OK on the hub's upstream
 * SUBSCRIBE closes its session PROTOCOL_VIOLATION (the moqsub model's
 * session fault). */
static void test_moqtrun_upsub_second_ok_closes(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok(sid);
  CHECK(moqtrun_test_count_kind(11) == 0);
  mups_ok(sid);
  CHECK(moqtrun_test_close_code() == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* The same for a REQUEST_ERROR after the SUBSCRIBE_OK (no REQUEST_UPDATE
 * outstanding, so it can only answer the SUBSCRIBE a second time). */
static void test_moqtrun_upsub_error_after_ok_closes(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_ok(sid);
  mtst_pub_err(SESS_A, sid, MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(moqtrun_test_close_code() == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* A SUBSCRIBE_OK on the hub's upstream SUBSCRIBE that does not decode
 * closes A's session PROTOCOL_VIOLATION; no track is claimed. */
static void test_moqtrun_upsub_ok_malformed_closes(void) {
  static const u8 cut[] = {0x40};
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mtrq_raw(SESS_A, (u64)mups_up_sid(), MOQCTL_T_SUBSCRIBE_OK, cut, sizeof cut);
  CHECK(moqtrun_test_close_code() == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use);
}

/* PUBLISH_DONE on the hub's SUBSCRIBE before any SUBSCRIBE_OK claimed a
 * track has no track to end: B keeps waiting for the answer. */
static void test_moqtrun_upsub_done_before_ok(void) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mups_done((u64)mups_up_sid(), MOQCTL_DONE_GOING_AWAY);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  CHECK(mups_used() == 1);
}

/* ===== the hub's REQUEST_UPDATE on a PUBLISH stream ===== */

#define MUPS_PUB_SID 12

/* A PUBLISHes the awaited track on its request stream MUPS_PUB_SID with
 * Track Property DYNAMIC_GROUPS 1, uint8 Parameter ptype = v (v 2:
 * absent). */
static void mups_pub_stream_p(u64 ptype, int v) {
  static u8             props[16];
  static moqctl_publish m;
  usz                   n    = 0;
  u64                   prev = 0;
  mtst_prop_num(props, &n, &prev, MOQTRUN_PROP_DYNAMIC_GROUPS, 1);
  m                  = (moqctl_publish){0};
  m.request_id       = mtst_rid += 4;
  m.name             = mrdv_f();
  m.track_alias      = MUPS_ALIAS;
  m.track_properties = wired_span_of(props, n);
  if (v < 2) {
    m.params.items[0].type = ptype;
    m.params.items[0].enc  = MOQCTL_PENC_UINT8;
    m.params.items[0].u8v  = (u8)v;
    m.params.n             = 1;
  }
  mtst_send(SESS_A, MUPS_PUB_SID, MOQCTL_T_PUBLISH, mtst_enc_publish, &m);
}

/* FORWARD fwd (2: absent). */
static void mups_pub_stream(int fwd) {
  mups_pub_stream_p(MOQCTL_PARAM_FORWARD, fwd);
}

/* REQUEST_UPDATEs the hub sent A on sid carrying ptype; the last one's
 * value in *v. */
static usz mups_upd_sent(u64 sid, u64 ptype, u64* v) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0;
    u64                      type;
    wired_span               body;
    moqtstat_update          m;
    if (c->s != SESS_A || c->stream_id != sid || c->kind != 3) {
      continue;
    }
    mt_peek_type(wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type != MOQTSTAT_T_REQUEST_UPDATE) {
      continue;
    }
    CHECK(
        moqtstat_update_take(
            mtst_ver(SESS_A), body, MOQCTL_PCTX_UPDATE_SUBSCRIPTION, &m) ==
        MOQCTL_OK);
    const moqctl_param* g = moqctl_params_find(&m.params, ptype);
    if (g) {
      *v = ptype == MOQCTL_PARAM_FORWARD ? g->u8v : g->vi;
      n++;
    }
  }
  return n;
}

static void mups_pub_init(int ver) {
  mrdv_init();
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = ver;
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = ver;
}

/* draft-22 7.6: "If at least one downstream subscriber for the Track is
 * not paused, the Relay MUST resume the upstream subscription with
 * REQUEST_UPDATE, if paused": a PUBLISH with FORWARD 0 gets FORWARD 1
 * once B subscribes unpaused, once only; A's REQUEST_OK is accepted on
 * the PUBLISH stream. An unpaused PUBLISH gets none. */
static void test_moqtrun_upsub_publish_resumed(void) {
  u64 v = 9;
  mups_pub_init(MOQVER_D22);
  mups_pub_stream(0);
  CHECK(mups_upd_sent(MUPS_PUB_SID, MOQCTL_PARAM_FORWARD, &v) == 0);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mups_upd_sent(MUPS_PUB_SID, MOQCTL_PARAM_FORWARD, &v) == 1 && v == 1);
  mtst_pub_ok(SESS_A, MUPS_PUB_SID);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(moqtrun_req_find(&mtst_hub, SESS_A, MUPS_PUB_SID)->upd_out == 0);
  mups_sub(SESS_B, MRDV_S2);
  CHECK(mups_upd_sent(MUPS_PUB_SID, MOQCTL_PARAM_FORWARD, &v) == 1);
  mups_pub_init(MOQVER_D22);
  mups_pub_stream(2);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mups_upd_sent(MUPS_PUB_SID, MOQCTL_PARAM_FORWARD, &v) == 0);
}

/* draft-23 9.19.18: the same with PAUSED (0x11, inverted): a moqt-23
 * PUBLISH with PAUSED 1 is resumed with PAUSED 0 -- decoded back here as
 * FORWARD 1, which a FORWARD on the wire would not be (unregistered in
 * draft-23, INVALID_PARAMETER). */
static void test_moqtrun_upsub_publish_resumed_d23(void) {
  u64 v = 9;
  mups_pub_init(MOQVER_D23);
  mups_pub_stream_p(MOQCTL_PARAM_PAUSED, 1);
  CHECK(mups_upd_sent(MUPS_PUB_SID, MOQCTL_PARAM_FORWARD, &v) == 0);
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mups_upd_sent(MUPS_PUB_SID, MOQCTL_PARAM_FORWARD, &v) == 1 && v == 1);
}

/* draft-18 10.2.13 on a PUBLISH-initiated track: B's NEW_GROUP_REQUEST
 * goes to A in a REQUEST_UPDATE on A's PUBLISH stream; A's REQUEST_ERROR
 * answers it there (no session close) and it is outstanding no more. */
static void test_moqtrun_upsub_ngr_on_publish(void) {
  u64 v = 9;
  mups_pub_init(MOQVER_D18);
  mups_pub_stream(2);
  mups_sub_ngr(SESS_B, MRDV_S1, 0);
  CHECK(
      mups_upd_sent(MUPS_PUB_SID, MOQCTL_PARAM_NEW_GROUP_REQUEST, &v) == 1 &&
      v == 0);
  mtst_pub_err(SESS_A, MUPS_PUB_SID, MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(!moqtrun_req_find(&mtst_hub, SESS_A, MUPS_PUB_SID)->ngr.out);
}

/* draft-18 10.2.13 on a PUBLISH-initiated track: while one
 * NEW_GROUP_REQUEST is outstanding a second of no greater value is held
 * back. */
static void test_moqtrun_upsub_ngr_on_publish_held(void) {
  u64 v = 9;
  mups_pub_init(MOQVER_D18);
  mtst_join(SESS_C);
  moqtrun_find_by_wt(&mtst_hub, SESS_C)->ver = MOQVER_D18;
  mups_pub_stream(2);
  mups_sub_ngr(SESS_B, MRDV_S1, 0);
  mups_sub_ngr(SESS_C, MRDV_S1, 0);
  CHECK(mups_upd_sent(MUPS_PUB_SID, MOQCTL_PARAM_NEW_GROUP_REQUEST, &v) == 1);
}

/* The hub's SUBSCRIBE stream to A, Established with DYNAMIC_GROUPS 1, B
 * subscribed and C, D joined; its stream id. */
static u64 mups_ngr_fixture(void) {
  mups_init();
  mtst_join(SESS_C);
  mtst_join(SESS_D);
  mups_sub(SESS_B, MRDV_S1);
  u64 sid = (u64)mups_up_sid();
  mups_ok_prop(sid, MOQTRUN_PROP_DYNAMIC_GROUPS, 1);
  return sid;
}

/* draft-18 10.2.13: A's REQUEST_ERROR answering the hub's REQUEST_UPDATE
 * on its SUBSCRIBE stream fails the update only -- the subscription
 * stands, and the NEW_GROUP_REQUEST is no longer outstanding. */
static void test_moqtrun_upsub_ngr_update_refused(void) {
  u64 got = 0;
  u64 sid = mups_ngr_fixture();
  mups_sub_ngr(SESS_C, MRDV_S1, 3);
  CHECK(mups_ngr_sent(sid, &got) == 1);
  mtst_pub_err(SESS_A, sid, MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(mups_used() == 1);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  mups_sub_ngr(SESS_D, MRDV_S1, 3);
  CHECK(mups_ngr_sent(sid, &got) == 2 && got == 3);
}

/* A refused REQUEST_UPDATE send leaves nothing outstanding: the next
 * NEW_GROUP_REQUEST goes out. */
static void test_moqtrun_upsub_ngr_send_refused(void) {
  u64 got                   = 0;
  u64 sid                   = mups_ngr_fixture();
  g_stream_send_reject_sess = SESS_A;
  mups_sub_ngr(SESS_C, MRDV_S1, 3);
  g_stream_send_reject_sess = 0;
  CHECK(mups_ngr_sent(sid, &got) == 1);
  mups_sub_ngr(SESS_D, MRDV_S1, 3);
  CHECK(mups_ngr_sent(sid, &got) == 2 && got == 3);
}

/* ===== GOAWAY on the hub's upstream SUBSCRIBE stream (draft-23 9.2) ===== */

/* A sends reps GOAWAYs (New Session URI of uri_n bytes, Timeout 0) on its
 * stream sid in one delivery. */
static void mups_goaways(u64 sid, usz reps, u8 uri_n) {
  u8  buf[32];
  usz n = 0;
  for (usz i = 0; i < reps; i++) {
    buf[n++] = MOQCTL_T_GOAWAY;
    buf[n++] = 0;
    buf[n++] = (u8)(2 + uri_n);
    buf[n++] = uri_n;
    for (u8 j = 0; j < uri_n; j++) {
      buf[n++] = 'x';
    }
    buf[n++] = 0;
  }
  mt_feed(&mtst_hub, SESS_A, sid, wired_span_of(buf, n), 0);
}

/* "the sender of the request SHOULD re-issue that specific request ...
 * (or the current session if no URI is provided), and close the old
 * request stream": a pending SUBSCRIBE goes out again to A on a new
 * stream under the next Request ID, the old one is cancelled, and A's
 * answer there reaches B. */
static void mups_goaway_reissues(void) {
  moqctl_subscribe m0, m1;
  i64              old, sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  old = mups_up(SESS_A, 0, &m0);
  mups_goaways((u64)old, 1, 0);
  sid = mups_up(SESS_A, 1, &m1);
  CHECK(sid >= 0 && sid != old);
  CHECK(m1.request_id == m0.request_id + 2);
  CHECK(mups_up_is((u64)old, "RST1|STOP1|"));
  CHECK(moqtrun_test_count_kind(11) == 0);
  mups_ok((u64)sid);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mups_used() == 1);
}

/* An Established one moves without ending B's subscription: B hears no
 * PUBLISH_DONE, and A's Objects under the new SUBSCRIBE_OK reach B. */
static void mups_goaway_moves_established(void) {
  moqctl_subscribe m;
  u8               buf[MOQTRUN_TEST_MAX_PAYLOAD];
  i64              old, sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  old = mups_up_sid();
  mups_ok((u64)old);
  mups_goaways((u64)old, 1, 0);
  sid = mups_up(SESS_A, 1, &m);
  CHECK(sid >= 0 && sid != old);
  CHECK(mups_up_is((u64)old, "RST1|STOP1|"));
  mups_ok((u64)sid);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mups_used() == 1);
  mt_feed(
      &mtst_hub, SESS_A, MUPS_DATA_SID,
      wired_span_of(buf, mups_stream(MUPS_ALIAS, buf)), 1);
  CHECK(mups_relayed_alias(SESS_B) == mrdv_alias(SESS_B, MRDV_S1));
}

/* "more than one GOAWAY ... on a single request stream" closes
 * UNEXPECTED_MESSAGE; a New Session URI sent to the hub, a server,
 * closes ROLE_VIOLATION. Neither re-issues. */
static void mups_goaway_refused(void) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mups_goaways((u64)mups_up_sid(), 2, 0);
  CHECK(mtrq_closes_cc(WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE) == 1);
  CHECK(mups_n_up(SESS_A) == 1);
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mups_goaways((u64)mups_up_sid(), 1, 1);
  CHECK(mtrq_closes_cc(WIRED_MOQTRUN_CLOSE_ROLE_VIOLATION) == 1);
  CHECK(mups_n_up(SESS_A) == 1);
}

/* Earlier drafts: the hub ignores it and keeps the request. */
static void mups_goaway_ignored(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid = (u64)mups_up_sid();
  mups_goaways(sid, 1, 0);
  CHECK(mups_n_up(SESS_A) == 1);
  CHECK(mups_up_is(sid, ""));
  CHECK(moqtrun_test_count_kind(11) == 0);
  mups_ok(sid);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
}

/* 9.2 "MUST NOT send ... SHOULD NOT initiate new requests" after a
 * control-stream GOAWAY: once A sent one, a GOAWAY on the hub's
 * SUBSCRIBE stream re-issues nothing toward A; the old request stays. */
static void mups_goaway_after_session_goaway(void) {
  u64 sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  sid                                                     = (u64)mups_up_sid();
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->sess.goaway_recv = 1;
  mups_goaways(sid, 1, 0);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mups_n_up(SESS_A) == 1 && mups_up_is(sid, ""));
  mups_ok(sid);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
}

/* With no stream to open the old request stays for now, and the next
 * sweep re-issues it once one opens. */
static void mups_goaway_retries(void) {
  i64 old;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  old                = mups_up_sid();
  g_open_bidi_fail_n = 1;
  mups_goaways((u64)old, 1, 0);
  CHECK(mups_up_is((u64)old, ""));
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mups_up_is((u64)old, "RST1|STOP1|"));
}

/* The re-issued SUBSCRIBE's SUBSCRIBE_OK may name a new Track Alias
 * (3.1.3 picks one per subscription): A's Objects under it reach B under
 * B's unchanged alias. */
static void mups_goaway_new_alias(void) {
  static moqctl_subscribe_ok ok;
  moqctl_subscribe           m;
  u8                         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  i64                        old, sid;
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  old = mups_up_sid();
  mups_ok((u64)old);
  mups_goaways((u64)old, 1, 0);
  sid            = mups_up(SESS_A, 1, &m);
  ok.track_alias = MUPS_ALIAS + 2;
  mtst_send(SESS_A, (u64)sid, MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
  mt_feed(
      &mtst_hub, SESS_A, MUPS_DATA_SID,
      wired_span_of(buf, mups_stream(MUPS_ALIAS + 2, buf)), 1);
  CHECK(mups_relayed_alias(SESS_B) == mrdv_alias(SESS_B, MRDV_S1));
  CHECK(moqtrun_test_count_kind(11) == 0);
}

static void test_moqtrun_upsub_goaway(void) {
  moqtrun_test_vers(MOQVER_CAP_REQ_GOAWAY23, 0, mups_goaway_reissues);
  moqtrun_test_vers(MOQVER_CAP_REQ_GOAWAY23, 0, mups_goaway_moves_established);
  moqtrun_test_vers(MOQVER_CAP_REQ_GOAWAY23, 0, mups_goaway_refused);
  moqtrun_test_vers(
      MOQVER_CAP_REQ_GOAWAY23, 0, mups_goaway_after_session_goaway);
  moqtrun_test_vers(MOQVER_CAP_REQ_GOAWAY23, 0, mups_goaway_retries);
  moqtrun_test_vers(MOQVER_CAP_REQ_GOAWAY23, 0, mups_goaway_new_alias);
  moqtrun_test_vers(0, MOQVER_CAP_REQ_GOAWAY23, mups_goaway_ignored);
}

/* B SUBSCRIBEs n distinct tracks chat/<room>/t<a+i> on request streams
 * MTRQ_ID(at + i), each sent upstream to announcer s; s Establishes the
 * first ones it has track slots for (WIRED_MOQTRUN_MAX_TRACKS_PER_PEER),
 * the rest stay pending. */
static void mups_ups_on(wired_wt_session* s, const char* room, usz at, usz n) {
  static char      names[WIRED_MOQTRUN_MAX_UP][3];
  moqctl_subscribe m;
  for (usz i = 0; i < n; i++) {
    static moqctl_subscribe_ok ok;
    names[at + i][0] = 't';
    names[at + i][1] = (char)('a' + i);
    moqctl_ftn f     = mtst_ftn("chat", room, names[at + i]);
    ok.track_alias   = 100 + i;
    mtst_subscribe_p(SESS_B, MTRQ_ID(at + i), &f, mtst_rid += 4, 0);
    i64 sid = mups_up(s, i, &m);
    CHECK(sid >= 0);
    if (i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER) {
      mtst_send(s, (u64)sid, MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
    }
  }
}

/* With every upstream SUBSCRIBE slot (WIRED_MOQTRUN_MAX_UP) in use --
 * Established tracks filling C's and D's track slots (chat/room2,
 * chat/room3) and A's (chat/room1), A holding one more still pending, so B
 * keeps under its WIRED_MOQTRUN_RDV_PER_SESSION waits -- a SUBSCRIBE of yet
 * another announced track cannot be sent upstream: B is refused at once
 * and nothing more goes to A. */
static void test_moqtrun_upsub_up_table_full(void) {
  const usz  per = WIRED_MOQTRUN_MAX_TRACKS_PER_PEER;
  const usz  na  = WIRED_MOQTRUN_MAX_UP - 2 * per;
  const u64  sid = MTRQ_ID(WIRED_MOQTRUN_MAX_UP);
  moqctl_ftn f   = mtst_ftn("chat", "room1", "zz");
  mups_init();
  mtst_join(SESS_C);
  mtst_join(SESS_D);
  mtns_pub(SESS_C, MRDV_S1, "chat/room2");
  mtns_pub(SESS_D, MRDV_S1, "chat/room3");
  mups_ups_on(SESS_C, "room2", 0, per);
  mups_ups_on(SESS_D, "room3", per, per);
  mups_ups_on(SESS_A, "room1", 2 * per, na);
  CHECK(mups_used() == WIRED_MOQTRUN_MAX_UP);
  mtst_subscribe_p(SESS_B, sid, &f, mtst_rid += 4, 0);
  CHECK(mtrq_type_on(12, sid) == MOQCTL_T_REQUEST_ERROR);
  CHECK(mups_n_up(SESS_A) == na);
}

void test_moqtrun_upsub(void) {
  test_moqtrun_upsub_up_table_full();
  test_moqtrun_upsub_goaway();
  test_moqtrun_upsub_dup_alias_closes();
  test_moqtrun_upsub_second_ok_closes();
  test_moqtrun_upsub_error_after_ok_closes();
  test_moqtrun_upsub_ok_malformed_closes();
  test_moqtrun_upsub_done_before_ok();
  test_moqtrun_upsub_redirect_uri_closes();
  moqtrun_test_allver(mtall_upsub);
  test_moqtrun_upsub_cross_draft();
  test_moqtrun_upsub_publish_resumed();
  test_moqtrun_upsub_publish_resumed_d23();
  test_moqtrun_upsub_ngr_on_publish();
  test_moqtrun_upsub_ngr_on_publish_held();
  test_moqtrun_upsub_ngr_update_refused();
  test_moqtrun_upsub_ngr_send_refused();
}
