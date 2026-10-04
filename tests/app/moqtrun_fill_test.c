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

void test_moqtrun_fill(void) { test_moqtrun_fill_subscribe_opens(); }
