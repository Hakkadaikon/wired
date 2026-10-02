/* Hub Object cache and FETCH (draft-ietf-moq-transport-19 10.12,
 * 10.13, 11.4.4). Real FETCH / SUBGROUP bytes go through the hub's
 * stream entry points; replies and fetch streams are read back from the
 * recording io stubs of moqtrun_test.c (same unity TU), reusing the
 * fixtures of moqtrun_sub_test.c. A "budget" of B bytes is an arena of B
 * payload bytes plus one MOQCACHE_HDR per record that has to fit. */

#define MF_ALIAS 1
#define MF_REQ 400 /* client bidi streams are 0 mod 4 (RFC 9000 2.1) */

static u8  mf_arena[64 * (MOQCACHE_HDR + 16)];
static u64 mf_pub_sid;
static u64 mf_ctrl_a;
static u64 mf_ctrl_b;

static moqctl_ftn mf_track(void) { return mtst_ftn("chat", "room1", "alice"); }

/* A publishes alice; B joins. cap 0 leaves the cache unattached. */
static void mf_init(usz cap) {
  moqctl_ftn f = mf_track();
  mtst_init();
  if (cap) wired_moqt_cache_attach(&mtst_hub, mf_arena, cap);
  mf_pub_sid = 2; /* client uni streams are 2 mod 4 */
  mf_ctrl_a  = mtst_join(SESS_A);
  mf_ctrl_b  = mtst_join(SESS_B);
  mtst_publish(SESS_A, mf_ctrl_a, &f, MF_ALIAS);
}

/* A sends Object {g, o} of n bytes (each 16*g+o) on its own stream. */
static void mf_obj(u64 g, u64 o, usz n) {
  u8             buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u8             pl[MOQTRUN_TEST_MAX_PAYLOAD];
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x30; /* mode 0b00, no properties, default priority */
  h.track_alias      = MF_ALIAS;
  h.group_id         = g;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  for (usz i = 0; i < n; i++) pl[i] = (u8)(16 * g + o);
  moqdata_obj_put(
      wired_mspan_of(buf, sizeof buf), &off, o, wired_span_of(pl, n));
  mf_pub_sid += 4;
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, mf_pub_sid, wired_span_of(buf, off), 1);
}

/* ===================== cache attach ===================== */

/* Whole Objects a publisher sends land in the attached arena. */
static void test_moqtrun_fetch_cache_attach(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 2);
  CHECK(mtst_hub.cache.used == MOQCACHE_HDR + 2);
}

/* Default: nothing attached, nothing cached. */
static void test_moqtrun_fetch_cache_default_off(void) {
  mf_init(0);
  mf_obj(0, 0, 2);
  CHECK(mtst_hub.cache.used == 0);
}

/* The publisher leaving releases its track's Objects. */
static void test_moqtrun_fetch_cache_released_on_leave(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 2);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mtst_hub.cache.used == 0);
}

/* A new PUBLISH of the name starts a new incarnation: the old Objects
 * go. */
static void test_moqtrun_fetch_cache_released_on_republish(void) {
  moqctl_ftn f = mf_track();
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 2);
  mtst_publish(SESS_A, mf_ctrl_a, &f, MF_ALIAS);
  CHECK(mtst_hub.cache.used == 0);
}

void test_moqtrun_fetch(void) {
  test_moqtrun_fetch_cache_attach();
  test_moqtrun_fetch_cache_default_off();
  test_moqtrun_fetch_cache_released_on_leave();
  test_moqtrun_fetch_cache_released_on_republish();
}
