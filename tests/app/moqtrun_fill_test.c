/* Hub fill fetch streams (draft-22 SS9.20.15 FILL_PARAMETERS): a
 * subscription's cached backlog served on a fetch data stream beside the
 * live subscription. Reuses the recording io stubs (moqtrun_test.c), the
 * subscription fixtures (moqtrun_sub_test.c) and the fetch-stream readers
 * (moqtrun_fetch_test.c) of the same unity TU. */

/* B SUBSCRIBEs to alice on draft-22 with FILL_PARAMETERS fill attached
 * (params list: the fill value, plus any extra in base); returns the
 * SUBSCRIBE's Request ID. */
static u8  mfill_val[64];
static u64 mfill_rid = 600;

static moqctl_params mfill_params(
    const moqfetch_fill* fill, const moqctl_params* base) {
  moqctl_params p = base ? *base : (moqctl_params){0};
  usz           n = 0;
  CHECK(
      moqfetch_fill_put(wired_mspan_of(mfill_val, sizeof mfill_val), &n, fill));
  p.items[p.n].type  = MOQCTL_PARAM_FILL_PARAMETERS;
  p.items[p.n].enc   = MOQCTL_PENC_BYTES;
  p.items[p.n].bytes = wired_span_of(mfill_val, n);
  p.n++;
  return p;
}

static u64 mfill_subscribe(
    const moqfetch_fill* fill, const moqctl_params* base) {
  moqctl_ftn    f                            = mf_track();
  moqctl_params p                            = mfill_params(fill, base);
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D22;
  mfill_rid += 2;
  mtst_subscribe_p(SESS_B, mf_ctrl_b, &f, mfill_rid, &p);
  return mfill_rid;
}

/* An open-ended fill on a fresh FORWARD-1 subscription: one uni stream,
 * FETCH_HEADER carrying the SUBSCRIBE's Request ID, the cached range in
 * ascending order, FIN at the end (SS9.20.15). */
static void test_moqtrun_fill_subscribe_opens(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  u64 rid = mfill_subscribe(&fill, 0);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_n == 2);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 1, 0, 1));
  CHECK(mf_fin);
}

/* Fetch streams opened toward B (FETCH_HEADER type byte). */
static usz mfill_opens(void) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) n += mf_opens(&g_calls[i]) != 0;
  return n;
}

/* An explicit fill end past the Largest Object is cut to it: nothing
 * past Largest is sent and nothing is waited for (SS9.20.15). */
static void test_moqtrun_fill_end_clipped_to_largest(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  fill.has_filter      = 1;
  fill.range.sk        = MOQCTL_RSK_ABS;
  fill.range.ek        = MOQCTL_REK_GROUP;
  fill.range.end_group = 1; /* past Largest {0,1} */
  mfill_subscribe(&fill, 0);
  CHECK(mf_read());
  CHECK(mf_n == 2);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 0, 1, 1));
  CHECK(mf_fin);
}

/* A fill starting past the Largest Object, or on a track with nothing
 * published, opens no stream; the subscription itself establishes. */
static void test_moqtrun_fill_empty_or_future_range(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  fill.has_filter        = 1;
  fill.range.sk          = MOQCTL_RSK_ABS;
  fill.range.start_group = 5;
  fill.range.ek          = MOQCTL_REK_UNBOUNDED;
  mfill_subscribe(&fill, 0);
  CHECK(mfill_opens() == 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  mf_init(sizeof mf_arena); /* nothing published at all */
  moqfetch_fill none = {0};
  mfill_subscribe(&none, 0);
  CHECK(mfill_opens() == 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
}

/* An open-ended filtered fill ends at the Largest Object current when
 * it is processed (SS9.20.9: an omitted end is Largest). */
static void test_moqtrun_fill_open_end_is_largest(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  fill.has_filter = 1;
  fill.range.sk   = MOQCTL_RSK_ABS;
  fill.range.ek   = MOQCTL_REK_UNBOUNDED;
  mfill_subscribe(&fill, 0);
  CHECK(mf_read());
  CHECK(mf_n == 2);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 1, 0, 1));
  CHECK(mf_fin);
}

/* B SUBSCRIBEs to alice on request stream MTRQ_S1 (draft-22) with params
 * (0 = none); returns the SUBSCRIBE's Request ID. */
static u64 mfill_subscribe_req(const moqctl_params* params) {
  moqctl_ftn f                               = mf_track();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D22;
  mfill_rid += 2;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, mfill_rid, params);
  return mfill_rid;
}

/* REQUEST_UPDATE carrying FILL_PARAMETERS on MTRQ_S1; returns its own
 * fresh Request ID (mtst_rid). */
static u64 mfill_update(const moqfetch_fill* fill, const moqctl_params* base) {
  moqctl_params p = mfill_params(fill, base);
  mtup_update(SESS_B, MTRQ_S1, &p);
  return mtst_rid;
}

/* A REQUEST_UPDATE without FILL_PARAMETERS opens no fill; one carrying
 * it opens a fill whose FETCH_HEADER has the REQUEST_UPDATE's Request ID,
 * and an earlier fill keeps running beside it (draft-22 9.8, 9.20.15). */
static void test_moqtrun_fill_update_opens(void) {
  moqfetch_fill fill  = {0};
  moqctl_params plain = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 7);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mfill_subscribe_req(0);
  mtup_update(SESS_B, MTRQ_S1, &plain);
  CHECK(mfill_opens() == 0);
  u64 rid = mfill_update(&fill, 0);
  CHECK(mfill_opens() == 1);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_n == 1 && mf_is_obj(0, 0, 0, 1));
  CHECK(mf_fin);
}

/* FORWARD gates every fill request: FILL_PARAMETERS on a FORWARD-0
 * SUBSCRIBE opens nothing, a plain FORWARD-1 resume does not revive it,
 * an update going 1 -> 0 with FILL_PARAMETERS opens nothing, and only
 * 0 -> 1 together with FILL_PARAMETERS opens the fill. */
static void test_moqtrun_fill_forward_gates(void) {
  moqfetch_fill fill = {0};
  moqctl_params p0   = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_params p1   = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  moqctl_params sub = mfill_params(&fill, &p0);
  mfill_subscribe_req(&sub);
  CHECK(mfill_opens() == 0);
  mtup_update(SESS_B, MTRQ_S1, &p1); /* plain resume */
  CHECK(mfill_opens() == 0);
  mfill_update(&fill, &p0); /* 1 -> 0 with a fill */
  CHECK(mfill_opens() == 0);
  u64 rid = mfill_update(&fill, &p1); /* 0 -> 1 with a fill */
  CHECK(mfill_opens() == 1);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
}

/* Two fills run at once: a SUBSCRIBE fill still draining and an update
 * fill opened beside it, each under its own Request ID; both drain to
 * FIN with no reset. */
static void test_moqtrun_fill_two_at_once(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  g_stream_send_ok_n = 0; /* streams open, rounds refused */
  moqctl_params sub  = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(mfill_opens() == 1);
  mfill_update(&fill, 0);
  CHECK(mfill_opens() == 2);
  CHECK(!mf_no_fetch());
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mf_no_fetch());
  CHECK(moqtrun_test_count_kind(7) == 0);
}

/* C's Object {g, o} of n bytes on a fresh one-shot stream (the
 * re-publishing session's twin of mf_obj). */
static void mfill_obj_c(u64 g, u64 o, usz n) {
  u8             buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u8             pl[MOQTRUN_TEST_MAX_PAYLOAD];
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x30;
  h.track_alias      = MF_ALIAS;
  h.group_id         = g;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  for (usz i = 0; i < n; i++) pl[i] = (u8)(16 * g + o);
  moqdata_obj_put(
      wired_mspan_of(buf, sizeof buf), &off, o, wired_span_of(pl, n));
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_C, 3002, wired_span_of(buf, off), 1);
}

/* A subscription revived by a new PUBLISH (no SUBSCRIBE round) is
 * filled only through REQUEST_UPDATE; the FETCH_HEADER carries that
 * update's Request ID. */
static void test_moqtrun_fill_publish_started_sub(void) {
  moqfetch_fill fill = {0};
  moqctl_ftn    f    = mf_track();
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mfill_subscribe_req(0);
  mtst_publish(SESS_C, mtst_join(SESS_C), &f, MF_ALIAS); /* supersedes A */
  moqtrun_test_reset();
  mfill_obj_c(0, 0, 2);
  CHECK(mtst_sub(SESS_C, SESS_B) != 0); /* re-attached by the PUBLISH */
  usz before = mfill_opens();
  u64 rid    = mfill_update(&fill, 0);
  CHECK(mfill_opens() == before + 1);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_n == 1 && mf_is_obj(0, 0, 0, 2));
  CHECK(mf_fin);
}

/* Reads B's last fetch stream as a fill stream (fills exist on draft-22
 * only, so 0x20C End of Timed-Out Range is legal on it, SS11.4.1). */
static int mfill_read(void) {
  moqfetch_seq seq  = {0};
  seq.eor_timed_out = 1;
  return mf_read_seq(seq);
}

/* Item i is an End of Timed-Out Range ending at {g, o}. */
static int mfill_is_tmo(usz i, u64 g, u64 o) {
  return i < mf_n && mf_items[i].flags == MOQFETCH_EOR_TIMED_OUT &&
         mf_items[i].group == g && mf_items[i].object == o;
}

/* A Location the cache cannot serve is reported at once as End of
 * Timed-Out Range (0x20C): the hub keeps no upstream FETCH, so it never
 * waits, whatever FILL_TIMEOUT says (SS9.20.15). */
static void test_moqtrun_fill_miss_is_timed_out_now(void) {
  moqfetch_fill fill = {0};
  fill.has_timeout   = 1;
  fill.timeout_ms    = 5000;
  mf_init(0); /* no cache: the whole range is a miss */
  mf_obj(0, 0, 1);
  mfill_subscribe(&fill, 0);
  CHECK(mfill_read());
  CHECK(mf_n == 1 && mfill_is_tmo(0, 0, 0));
  CHECK(mf_fin);
  mf_init(0);
  mf_obj(0, 0, 1);
  fill.timeout_ms = 0;
  mfill_subscribe(&fill, 0);
  CHECK(mfill_read());
  CHECK(mf_n == 1 && mfill_is_tmo(0, 0, 0));
  CHECK(mf_fin);
}

/* A run of evicted Locations is one 0x20C naming the run's end, the
 * remaining Objects follow and the fill still FINs only after the whole
 * range (SS11.4.1, SS9.20.15). */
static void test_moqtrun_fill_evicted_run_collapsed(void) {
  moqfetch_fill fill = {0};
  mf_init(2 * (MOQCACHE_HDR + 1));
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1); /* evicts group 0 */
  mf_obj(1, 1, 1);
  mfill_subscribe(&fill, 0);
  CHECK(mfill_read());
  CHECK(mf_n == 3);
  CHECK(mfill_is_tmo(0, 0, MOQCACHE_OBJ_ID_MAX));
  CHECK(mf_is_obj(1, 1, 0, 1) && mf_is_obj(2, 1, 1, 1));
  CHECK(mf_fin);
}

/* An eviction while the fill is underway (cursor parked on a refused
 * round) turns the pending Location into 0x20C, never stale bytes, and
 * the fill continues to FIN. */
static void test_moqtrun_fill_eviction_under_cursor(void) {
  moqfetch_fill fill = {0};
  mf_init(4 * (MOQCACHE_HDR + 1));
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_obj(1, 1, 1);
  g_stream_send_ok_n = 1;
  mfill_subscribe(&fill, 0);
  mf_obj(2, 0, 1); /* evicts group 0 */
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mfill_read());
  CHECK(mf_is_obj(0, 0, 0, 1));
  CHECK(mfill_is_tmo(1, 0, MOQCACHE_OBJ_ID_MAX));
  CHECK(mf_fin);
}

void test_moqtrun_fill(void) {
  test_moqtrun_fill_subscribe_opens();
  test_moqtrun_fill_end_clipped_to_largest();
  test_moqtrun_fill_empty_or_future_range();
  test_moqtrun_fill_open_end_is_largest();
  test_moqtrun_fill_update_opens();
  test_moqtrun_fill_forward_gates();
  test_moqtrun_fill_two_at_once();
  test_moqtrun_fill_publish_started_sub();
  test_moqtrun_fill_miss_is_timed_out_now();
  test_moqtrun_fill_evicted_run_collapsed();
  test_moqtrun_fill_eviction_under_cursor();
}
