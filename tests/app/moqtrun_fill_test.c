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

void test_moqtrun_fill(void) {
  test_moqtrun_fill_subscribe_opens();
  test_moqtrun_fill_end_clipped_to_largest();
  test_moqtrun_fill_empty_or_future_range();
  test_moqtrun_fill_open_end_is_largest();
}
