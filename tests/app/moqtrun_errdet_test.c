/* draft-ietf-moq-transport-23 9.4.2 REQUEST_ERROR Error Details through
 * the hub: the Redirect a publisher answers with, the UNSUPPORTED_PROPERTY
 * details the hub sends and relays. Shares the fixtures of
 * moqtrun_test.c, moqtrun_sub_test.c, moqtrun_subtracks_test.c,
 * moqtrun_sess_test.c, moqtrun_rdv_test.c and moqtrun_upsub_test.c (same
 * unity TU). */

static int mted_enc23(wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_error_encode23(buf, off, m);
}

/* The last REQUEST_ERROR on s's stream sid, decoded in s's draft into *e;
 * 1 when there is one. */
static int mted_err(wired_wt_session* s, u64 sid, moqctl_request_error* e) {
  int found = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c   = &g_calls[i];
    usz                      off = 0, boff = 0;
    u64                      type = 0;
    wired_span               body;
    if (c->s != s || c->stream_id != sid || (c->kind != 3 && c->kind != 12)) {
      continue;
    }
    mt_peek_type(wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    if (type == MOQCTL_T_REQUEST_ERROR) {
      found =
          moqctl_request_error_take_v(mtst_ver(s), body, &boff, e) == MOQCTL_OK;
    }
  }
  return found;
}

/* 9.4.2.2: a PUBLISH with Mandatory Track Properties 0x4000 and 0x7FFF
 * is refused UNSUPPORTED_EXTENSION naming both, one UNSUPPORTED_PROPERTY
 * each, in order; draft-18..22 carry no Error Details. */
static void mted_publish_mandatory(void) {
  u8                   props[32];
  usz                  n    = 0;
  u64                  prev = 0;
  moqctl_request_error e    = {0};
  moqctl_ftn           f    = mtst_ftn("chat", "room1", "alice");
  int d23 = (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_ERR_DETAILS) != 0;
  mtst_prop_num(props, &n, &prev, 0x4000, 1);
  mtst_prop_num(props, &n, &prev, 0x7FFF, 1);
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_publish_props(SESS_A, ca, &f, 1, wired_span_of(props, n));
  CHECK(mted_err(SESS_A, ca, &e));
  CHECK(e.error_code == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  CHECK(e.n_unsupported == (d23 ? 2 : 0));
  CHECK(!d23 || (e.unsupported[0] == 0x4000 && e.unsupported[1] == 0x7FFF));
}

/* 9.4.2.2: the upstream SUBSCRIBE_OK names Mandatory Track Property
 * 0x4000: the waiter's UNSUPPORTED_EXTENSION carries it. */
static void test_mted_upsub_ok_mandatory_d23(void) {
  moqctl_request_error e = {0};
  mups_init_v(MOQVER_D23, MOQVER_D23);
  mups_sub(SESS_B, MRDV_S1);
  mups_ok_prop((u64)mups_up_sid(), 0x4000, 1);
  CHECK(mted_err(SESS_B, MRDV_S1, &e));
  CHECK(e.error_code == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  CHECK(e.n_unsupported == 1 && e.unsupported[0] == 0x4000);
}

/* 9.4.2.2: the publisher's UNSUPPORTED_EXTENSION with its
 * UNSUPPORTED_PROPERTY details goes on to the waiter with them. */
static void test_mted_upsub_error_relays_details_d23(void) {
  static moqctl_request_error up;
  moqctl_request_error        e = {0};
  u8                          msg[64];
  mups_init_v(MOQVER_D23, MOQVER_D23);
  mups_sub(SESS_B, MRDV_S1);
  up.error_code     = MOQCTL_ERR_UNSUPPORTED_EXTENSION;
  up.n_unsupported  = 2;
  up.unsupported[0] = 0x4100;
  up.unsupported[1] = 0x4200;
  usz n             = moqtrun_envelope_put(
      MOQVER_D22, wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_ERROR,
      mted_enc23, &up);
  mt_feed(&mtst_hub, SESS_A, (u64)mups_up_sid(), wired_span_of(msg, n), 0);
  CHECK(mted_err(SESS_B, MRDV_S1, &e));
  CHECK(e.error_code == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  CHECK(e.n_unsupported == 2);
  CHECK(e.unsupported[0] == 0x4100 && e.unsupported[1] == 0x4200);
}

/* The hub's PUBLISH (B's SUBSCRIBE_TRACKS) answered by a draft-23
 * REQUEST_ERROR e; the session close code, ~0 for none. */
static u64 mted_publish_answered(const moqctl_request_error* e) {
  u64 sid                                    = mtss_hub_publish();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D23;
  mtst_send(SESS_B, sid, MOQCTL_T_REQUEST_ERROR, mted_enc23, e);
  return moqtrun_test_close_code();
}

/* 9.4.2.1: REDIRECT with no REDIRECT detail is MALFORMED_MESSAGE; a
 * Redirect with a Connect URI sent to the server ROLE_VIOLATION; one with
 * an empty Connect URI is taken. */
static void test_mted_redirect_d23(void) {
  static moqctl_request_error e;
  e.error_code = MOQCTL_ERR_REDIRECT;
  CHECK(mted_publish_answered(&e) == WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE);
  e.has_redirect         = 1;
  e.redirect.connect_uri = mtst_z("https://r.example/moq");
  CHECK(mted_publish_answered(&e) == WIRED_MOQTRUN_CLOSE_ROLE_VIOLATION);
  e.redirect.connect_uri = wired_span_of(0, 0);
  e.redirect.track_name  = mtst_z("z");
  CHECK(mted_publish_answered(&e) == ~(u64)0);
}

/* REQUEST_ERROR REDIRECT, empty Connect URI, Track Name name. */
static const moqctl_request_error* mted_redirect(wired_span name) {
  static moqctl_request_error e;
  e                     = (moqctl_request_error){0};
  e.error_code          = MOQCTL_ERR_REDIRECT;
  e.has_redirect        = 1;
  e.redirect.track_name = name;
  return &e;
}

static moqtrun_body_encode_fn mted_enc_for(int ver) {
  return (moqver_caps(ver) & MOQVER_CAP_ERR_DETAILS)
             ? mted_enc23
             : mtsub_encode_request_error;
}

/* The hub's upstream SUBSCRIBE (A on pv, B on sv) answered by a Redirect
 * to Track Name name; the session close code, ~0 for none. */
static u64 mted_upsub_redirect(int pv, int sv, wired_span name) {
  mups_init_v(pv, sv);
  mups_sub(SESS_B, MRDV_S1);
  mtst_send(
      SESS_A, (u64)mups_up_sid(), MOQCTL_T_REQUEST_ERROR, mted_enc_for(pv),
      mted_redirect(name));
  return moqtrun_test_close_code();
}

/* draft-23 2.4.1 / 9.4.2.1: a SUBSCRIBE is track-scoped, so a Redirect
 * with an empty Track Name closes the publisher's session
 * PROTOCOL_VIOLATION; draft-18..22 take it. A named one is taken. */
static void mted_upsub_redirect_empty(void) {
  int d23 =
      (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_TRACK_NAME_NONEMPTY) != 0;
  int v = g_moqtrun_test_ver;
  CHECK(
      mted_upsub_redirect(v, v, wired_span_of(0, 0)) ==
      (d23 ? WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION : ~(u64)0));
  CHECK(mted_upsub_redirect(v, v, mtst_z("z")) == ~(u64)0);
}

/* draft-23 9.4.2.1: REDIRECT needs a REDIRECT detail, whose Track Name a
 * draft-23 receiver must find non-empty (2.4.1): a draft-22 upstream's
 * empty-name Redirect reaches a draft-23 waiter as INTERNAL_ERROR. */
static void test_mted_upsub_redirect_relay_d23(void) {
  moqctl_request_error e = {0};
  CHECK(
      mted_upsub_redirect(MOQVER_D22, MOQVER_D23, wired_span_of(0, 0)) ==
      ~(u64)0);
  CHECK(mted_err(SESS_B, MRDV_S1, &e));
  CHECK(e.error_code == MOQCTL_ERR_INTERNAL_ERROR && !e.has_redirect);
}

void test_moqtrun_errdet(void) {
  moqtrun_test_vers(0, 0, mted_publish_mandatory);
  moqtrun_test_vers(0, 0, mted_upsub_redirect_empty);
  test_mted_upsub_redirect_relay_d23();
  test_mted_upsub_ok_mandatory_d23();
  test_mted_upsub_error_relays_details_d23();
  test_mted_redirect_d23();
}
