/* draft-ietf-moq-transport-23 12.2: the session close code per cause,
 * table-driven over every draft -- draft-23 names a specific code where
 * draft-18..22 close PROTOCOL_VIOLATION (or KEY_VALUE_FORMATTING_ERROR),
 * and the older drafts keep their code. Shares the fixtures of
 * moqtrun_test.c, moqtrun_sub_test.c, moqtrun_ctlfix_test.c and
 * moqtrun_sess_test.c (same unity TU). */

/* A token session on SESS_A whose client SETUP carries the Setup Option
 * bytes opt; the close code, ~0 for none. */
static u64 mtcc_setup(const u8* opt, usz n) {
  wired_moqt_hub hub;
  u8             msg[80];
  usz            len = mtctl_uni_ctl(msg, opt, n);
  mtcf_token_session(&hub);
  mtcf_part(&hub, 2, msg, 0, len);
  return moqtrun_test_close_code();
}

/* B sends raw message type + body on a fresh request stream. */
static u64 mtcc_req(u64 type, const u8* body, usz n) {
  mtrq_setup();
  mtrq_raw(SESS_B, MTRQ_S1, type, body, n);
  return moqtrun_test_close_code();
}

/* B sends raw message type + body on its control stream. */
static u64 mtcc_ctl(u64 type, const u8* body, usz n) {
  mtrq_setup();
  mtrq_raw(SESS_B, mtdr_ctl(SESS_B), type, body, n);
  return moqtrun_test_close_code();
}

/* 9: a SUBSCRIBE cut inside its Track Namespace does not match its
 * Length: MALFORMED_MESSAGE. */
static u64 mtcc_body_short(void) {
  static const u8 b[] = {0x00, 0x01, 0x04, 'c'};
  return mtcc_req(MOQCTL_T_SUBSCRIBE, b, sizeof b);
}

/* 8.7: a Track Namespace Field of length 0: INVALID_TRACK_NAMESPACE. */
static u64 mtcc_ns_empty_field(void) {
  static const u8 b[] = {0x00, 0x01, 0x00};
  return mtcc_req(MOQCTL_T_SUBSCRIBE, b, sizeof b);
}

/* 8.7: 33 Track Namespace Fields: INVALID_TRACK_NAMESPACE. */
static u64 mtcc_ns_33_fields(void) {
  static const u8 b[] = {0x00, 0x21};
  return mtcc_req(MOQCTL_T_SUBSCRIBE, b, sizeof b);
}

/* 9.2: a New Session URI Length of 8193 (vi64 0xA0 0x01): FIELD_LENGTH_
 * EXCEEDED, judged before its bytes. */
static u64 mtcc_goaway_uri_long(void) {
  static const u8 b[] = {0xA0, 0x01};
  return mtcc_ctl(MOQCTL_T_GOAWAY, b, sizeof b);
}

/* 9.10: PUBLISH_STATE_NOTIFY on the control stream (an unknown type
 * before draft-22): UNEXPECTED_MESSAGE. */
static u64 mtcc_psn_on_ctl(void) {
  static const u8 b[] = {0x00, 0x00};
  return mtcc_ctl(MOQCTL_T_PUBLISH_STATE_NOTIFY, b, sizeof b);
}

/* 9.19.8: GROUP_ORDER 3 in a SUBSCRIBE: INVALID_PARAMETER. */
static u64 mtcc_param_range(void) {
  moqctl_params p = mtst_params_u8(MOQCTL_PARAM_GROUP_ORDER, 3);
  moqctl_ftn    f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p);
  return moqtrun_test_close_code();
}

/* 8.9: a SUBSCRIBE AUTHORIZATION TOKEN that does not decode (USE_VALUE
 * without its Token Type): MALFORMED_AUTH_TOKEN, KEY_VALUE_FORMATTING_ERROR
 * (0x6) before draft-23. */
static u64 mtcc_token_bad(void) {
  static const u8 bad[] = {0x03};
  moqctl_ftn      f     = mtrq_setup();
  moqctl_params   p     = mtcf_param(MOQCTL_PARAM_AUTHORIZATION_TOKEN);
  p.items[0].bytes      = wired_span_of(bad, sizeof bad);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, &p);
  return moqtrun_test_close_code();
}

/* 9.1.4: a SETUP AUTHORIZATION TOKEN of Alias Type DELETE sent to the
 * server: ROLE_VIOLATION. */
static u64 mtcc_setup_token_delete(void) {
  static const u8 del[] = {0x03, 0x02, 0x00, 0x07};
  return mtcc_setup(del, sizeof del);
}

/* 8.3: Setup Option Types past 2^64-1 -- Delta Type 2^64-2 (the 9-byte
 * vi64 FF FF FF FF FF FF FF FF FE), then Delta 2: DELTA_ENCODING_OVERFLOW. */
static u64 mtcc_setup_delta(void) {
  static const u8 opt[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFE, 0x00, 0x02, 0x00};
  return mtcc_setup(opt, sizeof opt);
}

/* 8.3: an odd Setup Option of Length 65536 (vi64 0xC1 0x00 0x00):
 * FIELD_LENGTH_EXCEEDED. */
static u64 mtcc_setup_kvp_long(void) {
  static const u8 opt[] = {0x07, 0xC1, 0x00, 0x00};
  return mtcc_setup(opt, sizeof opt);
}

typedef struct {
  u64 (*run)(void);
  u64 before; /* draft-18..22 */
  u64 d23;
} mtcc_case;

static const mtcc_case mtcc_cases[] = {
    {mtcc_body_short, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE},
    {mtcc_ns_empty_field, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_TRACK_NAMESPACE},
    {mtcc_ns_33_fields, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_TRACK_NAMESPACE},
    {mtcc_goaway_uri_long, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_FIELD_LENGTH_EXCEEDED},
    {mtcc_psn_on_ctl, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE},
    {mtcc_param_range, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_PARAMETER},
    {mtcc_token_bad, WIRED_MOQTRUN_CLOSE_MALFORMED_KEY_VALUE,
     WIRED_MOQTRUN_CLOSE_MALFORMED_AUTH_TOKEN},
    {mtcc_setup_token_delete, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_ROLE_VIOLATION},
    {mtcc_setup_delta, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_DELTA_ENCODING_OVERFLOW},
    {mtcc_setup_kvp_long, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_FIELD_LENGTH_EXCEEDED},
};

/* Every case under the harness draft (moqtrun_test_vers). */
static void mtcc_all_cases(void) {
  int d23 = (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_CLOSE_CODES23) != 0;
  for (usz i = 0; i < sizeof mtcc_cases / sizeof mtcc_cases[0]; i++) {
    const mtcc_case* c    = &mtcc_cases[i];
    u64              got  = c->run();
    u64              want = d23 ? c->d23 : c->before;
    CHECK(got == want);
    if (got != want) {
      printf(
          "  ^ close case %u got 0x%llx\n", (unsigned)i,
          (unsigned long long)got);
    }
  }
}

/* Only moqt-23 carries the new codes. */
static void test_mtcc_cap_only_d23(void) {
  for (int v = 0; v < MOQVER_COUNT; v++) {
    CHECK(
        ((moqver_caps(v) & MOQVER_CAP_CLOSE_CODES23) != 0) ==
        (v == MOQVER_D23));
  }
}

void test_moqtrun_cc(void) {
  test_mtcc_cap_only_d23();
  moqtrun_test_vers(0, 0, mtcc_all_cases);
}
