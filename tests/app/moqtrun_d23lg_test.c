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
}
