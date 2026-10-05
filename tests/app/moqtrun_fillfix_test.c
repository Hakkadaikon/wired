/* Fill fetch stream fixes from the MoqtFillLife TLC counterexamples
 * (ledger 12-14..12-16): an omitted fill LOCATION_FILTER inherits the
 * subscription's (draft-22 SS3.4), a malformed FILL_PARAMETERS closes the
 * session before any reply (SS9.20.15, SS9.20), a fill the full tables
 * cannot hold is refused before the reply (SS3.4.1), and a retired track
 * resets its fills INTERNAL_ERROR (ruling Q-08). Reuses the fill fixtures
 * of moqtrun_fill_test.c in the same unity TU. */

static u8 mffx_val[16];

/* params (base plus) a FILL_PARAMETERS whose value is raw bytes v. */
static moqctl_params mffx_raw(wired_span v, const moqctl_params* base) {
  moqctl_params p    = base ? *base : (moqctl_params){0};
  p.items[p.n].type  = MOQCTL_PARAM_FILL_PARAMETERS;
  p.items[p.n].enc   = MOQCTL_PENC_BYTES;
  p.items[p.n].bytes = v;
  p.n++;
  return p;
}

/* A FILL_PARAMETERS value without LOCATION_FILTER: GROUP_ORDER Ascending
 * alone (one parameter, so the value is not zero-length). */
static moqctl_params mffx_no_lf(const moqctl_params* base) {
  moqctl_params in = {0};
  usz           n  = 0;
  in.items[0].type = MOQCTL_PARAM_GROUP_ORDER;
  in.items[0].enc  = MOQCTL_PENC_UINT8;
  in.items[0].u8v  = 1;
  in.n             = 1;
  CHECK(moqctl_params_put(wired_mspan_of(mffx_val, sizeof mffx_val), &n, &in));
  return mffx_raw(wired_span_of(mffx_val, n), base);
}

/* A publishes groups 0, 1 and 2 (one Object each). */
static void mffx_three_groups(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  mf_obj(2, 0, 1);
}

static moqctl_params mffx_sub_filter(moqctl_rsk sk, u64 g) {
  return mt22_filter(1, mt22_rl(sk, g, 0, MOQCTL_REK_UNBOUNDED, 0, 0));
}

/* 12-14: omitted fill filter under a Next Object subscription -- the
 * fill range is Next Object evaluated as a Fetch: past Largest, so no
 * fill stream opens; the subscription itself is accepted. */
static void test_moqtrun_fillfix_omitted_next_object(void) {
  moqctl_params base = mffx_sub_filter(MOQCTL_RSK_NEXT_OBJ, 0);
  mffx_three_groups();
  moqctl_params sub = mffx_no_lf(&base);
  mfill_subscribe_req(&sub);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(mfill_opens() == 0);
}

/* 12-14: omitted fill filter under AbsoluteStart{1,0}: the fill starts
 * at group 1, never group 0. */
static void test_moqtrun_fillfix_omitted_abs_start(void) {
  moqctl_params base = mffx_sub_filter(MOQCTL_RSK_ABS, 1);
  mffx_three_groups();
  moqctl_params sub = mffx_no_lf(&base);
  u64           rid = mfill_subscribe_req(&sub);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_n == 2 && mf_is_obj(0, 1, 0, 1) && mf_is_obj(1, 2, 0, 1));
  CHECK(mf_fin);
}

/* 12-14 guard (Q-02): an explicit 0x00 fill filter, and a zero-length
 * FILL_PARAMETERS value, both fill the whole track whatever the
 * subscription's own filter. */
static void test_moqtrun_fillfix_explicit_none_whole(void) {
  moqfetch_fill none = {0};
  moqctl_params base = mffx_sub_filter(MOQCTL_RSK_NEXT_OBJ, 0);
  mffx_three_groups();
  moqctl_params sub = mfill_params(&none, &base); /* LOCATION_FILTER 0x00 */
  mfill_subscribe_req(&sub);
  CHECK(mf_read());
  CHECK(mf_n == 3 && mf_is_obj(0, 0, 0, 1));
  base = mffx_sub_filter(MOQCTL_RSK_ABS, 1);
  mffx_three_groups();
  sub = mffx_raw(wired_span_of(mffx_val, 0), &base); /* zero-length */
  mfill_subscribe_req(&sub);
  CHECK(mf_read());
  CHECK(mf_n == 3 && mf_is_obj(0, 0, 0, 1));
}

/* 12-14 on REQUEST_UPDATE: an omitted fill filter inherits the
 * subscription's filter as the update left it. */
static void test_moqtrun_fillfix_omitted_update(void) {
  moqctl_params base = mffx_sub_filter(MOQCTL_RSK_ABS, 2);
  mffx_three_groups();
  mfill_subscribe_req(&base);
  moqctl_params upd = mffx_no_lf(0);
  mtup_update(SESS_B, MTRQ_S1, &upd);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == mtst_rid);
  CHECK(mf_n == 1 && mf_is_obj(0, 2, 0, 1));
}

/* Malformed FILL_PARAMETERS values: a truncated LOCATION_FILTER (type
 * 0x02 without its Locations) and an unknown inner parameter type. */
static const u8 MFFX_TRUNC[]   = {0x01, 0x21, 0x02};
static const u8 MFFX_UNKNOWN[] = {0x01, 0x3e, 0x00};

static usz mffx_pv_closes(void) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++)
    n += g_calls[i].kind == 11 && g_calls[i].s == SESS_B &&
         g_calls[i].stream_id == WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION;
  return n;
}

/* 12-15: a malformed FILL_PARAMETERS on SUBSCRIBE closes the session
 * with PROTOCOL_VIOLATION and no SUBSCRIBE_OK goes out. */
static void mffx_malformed_sub(wired_span v) {
  mffx_three_groups();
  moqctl_params sub = mffx_raw(v, 0);
  mfill_subscribe_req(&sub);
  CHECK(mffx_pv_closes() == 1);
  CHECK(mtrq_type_on(12, MTRQ_S1) == 0);
  CHECK(mtrq_type_on(3, MTRQ_S1) == 0);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  CHECK(mfill_opens() == 0);
}

static void test_moqtrun_fillfix_malformed_subscribe(void) {
  mffx_malformed_sub(wired_span_of(MFFX_TRUNC, sizeof MFFX_TRUNC));
  mffx_malformed_sub(wired_span_of(MFFX_UNKNOWN, sizeof MFFX_UNKNOWN));
}

/* 12-15: the same on REQUEST_UPDATE -- closed, no REQUEST_OK for it. */
static void test_moqtrun_fillfix_malformed_update(void) {
  mffx_three_groups();
  mfill_subscribe_req(0);
  usz           before = g_n_calls;
  moqctl_params upd = mffx_raw(wired_span_of(MFFX_TRUNC, sizeof MFFX_TRUNC), 0);
  mtup_update(SESS_B, MTRQ_S1, &upd);
  CHECK(mffx_pv_closes() == 1);
  for (usz i = before; i < g_n_calls; i++)
    CHECK(!(g_calls[i].kind == 3 && g_calls[i].stream_id == MTRQ_S1));
  CHECK(mfill_opens() == 0);
}

/* Every fetches[] slot holds a parked plain FETCH, every fetch_waits[]
 * slot a held fill of another (absent) session. */
static void mffx_fill_tables(void) {
  mfill_occupy_slots();
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    mtst_hub.fetch_waits[i].in_use  = 1;
    mtst_hub.fetch_waits[i].is_fill = 1;
    mtst_hub.fetch_waits[i].wt      = SESS_C;
  }
}

/* 12-16: a fill neither table can hold is refused before SUBSCRIBE_OK:
 * REQUEST_ERROR INTERNAL_ERROR, no subscription, no stream. */
static void test_moqtrun_fillfix_full_subscribe_refused(void) {
  moqfetch_fill fill = {0};
  mffx_three_groups();
  mffx_fill_tables();
  moqctl_params sub = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(mtrq_err_on(MTRQ_S1) == MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  CHECK(mfill_opens() == WIRED_MOQTRUN_MAX_FETCHES);
}

/* 12-16: a SUBSCRIBE whose fill would open nothing (an empty range)
 * needs no room and is accepted with full tables. */
static void test_moqtrun_fillfix_full_empty_fill_ok(void) {
  moqfetch_fill fill     = {0};
  fill.has_filter        = 1;
  fill.range.sk          = MOQCTL_RSK_ABS;
  fill.range.start_group = 5; /* past Largest */
  mffx_three_groups();
  mffx_fill_tables();
  moqctl_params sub = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
}

/* 12-16 on REQUEST_UPDATE: refused with REQUEST_ERROR before any
 * REQUEST_OK, no fill stream. */
static void test_moqtrun_fillfix_full_update_refused(void) {
  moqfetch_fill fill = {0};
  mffx_three_groups();
  mffx_fill_tables(); /* its FETCHes use B's pre-draft-22 layout */
  mfill_subscribe_req(0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  mfill_update(&fill, 0);
  CHECK(mtrq_err_on(MTRQ_S1) == MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(mfill_opens() == WIRED_MOQTRUN_MAX_FETCHES);
}

/* Q-08: the upstream track retired (superseded by a newer PUBLISH of the
 * name) resets an open fill INTERNAL_ERROR rather than ending it with a
 * Timed-Out marker and FIN. */
static void test_moqtrun_fillfix_retire_resets(void) {
  moqfetch_fill fill = {0};
  moqctl_ftn    f    = mf_track();
  mffx_three_groups();
  g_stream_send_ok_n = 0; /* the fill parks mid-range, opened */
  moqctl_params sub  = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(!mf_no_fetch());
  g_stream_send_ok_n = -1;
  mtst_publish(SESS_C, mtst_join(SESS_C), &f, MF_ALIAS + 1);
  CHECK(mfill_reset_code(mfill_sid(0)) == MOQTRUN_RESET_INTERNAL_ERROR);
  CHECK(mf_no_fetch());
}

static void mtall_fillfix(void) {
  test_moqtrun_fillfix_omitted_next_object();
  test_moqtrun_fillfix_omitted_abs_start();
  test_moqtrun_fillfix_explicit_none_whole();
  test_moqtrun_fillfix_omitted_update();
  test_moqtrun_fillfix_malformed_subscribe();
  test_moqtrun_fillfix_malformed_update();
  test_moqtrun_fillfix_retire_resets();
}

/* Table-filling scenarios park draft-18/19-layout FETCHes (mf_standalone),
 * as moqtrun_fill_test.c's slot-full ones do. */
static void mtall_fillfix_fetch19(void) {
  test_moqtrun_fillfix_full_subscribe_refused();
  test_moqtrun_fillfix_full_empty_fill_ok();
  test_moqtrun_fillfix_full_update_refused();
}

void test_moqtrun_fillfix(void) {
  moqtrun_test_allver(mtall_fillfix);
  moqtrun_test_vers(0, MOQVER_CAP_FETCH_BODY_V22, mtall_fillfix_fetch19);
}
