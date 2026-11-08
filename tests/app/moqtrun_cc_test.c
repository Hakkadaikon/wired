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

/* 9.10: PUBLISH_STATE_NOTIFY from the subscriber on its SUBSCRIBE's
 * stream (the hub publishes there): ROLE_VIOLATION. */
static u64 mtcc_psn_from_subscriber(void) {
  static const u8 b[] = {0x00, 0x00};
  moqctl_ftn      f   = mtrq_setup();
  mtst_subscribe(SESS_B, MTRQ_S1, &f);
  mtrq_raw(SESS_B, MTRQ_S1, MOQCTL_T_PUBLISH_STATE_NOTIFY, b, sizeof b);
  return moqtrun_test_close_code();
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

/* A's uni stream 14: SUBGROUP_HEADER Type type + obj (fin as given). */
static u64 mtcc_sg(u64 type, const u8* obj, usz n, int fin) {
  u8 b[64];
  mtrq_setup();
  mtss_uni(14, b, mtss_sg(b, type, obj, n), fin);
  return moqtrun_test_close_code();
}

/* 11.1.1: an unregistered Object Status (0x7F): INVALID_OBJECT_STATUS. */
static u64 mtcc_sg_status(void) {
  static const u8 obj[] = {0x00, 0x00, 0x7F};
  return mtcc_sg(0x10, obj, sizeof obj, 0);
}

/* 11.1.2: Properties on an End of Group Object: INVALID_OBJECT_STATUS. */
static u64 mtcc_sg_props_eog(void) {
  static const u8 obj[] = {0x00, 0x02, 0x02, 0x05, 0x00, 0x03};
  return mtcc_sg(0x11, obj, sizeof obj, 0);
}

/* 11.3.1: Object ID Delta 2^64-1 after Object 0 wraps:
 * DELTA_ENCODING_OVERFLOW. */
static u64 mtcc_sg_id_wrap(void) {
  static const u8 obj[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0x01, 'a',  0x00, 0x01, 'b'};
  return mtcc_sg(0x10, obj, sizeof obj, 0);
}

/* 11.3: a FIN inside a serialized Object: TRUNCATED_OBJECT. */
static u64 mtcc_sg_fin_torn(void) {
  static const u8 obj[] = {0x00, 0x05, 'h', 'i'};
  return mtcc_sg(0x10, obj, sizeof obj, 1);
}

/* 6.4.1: an unknown uni Stream Type (0x01): INVALID_STREAM_HEADER. */
static u64 mtcc_uni_unknown(void) {
  static const u8 b[] = {0x01, 0x01, 0x00, 0x00};
  mtrq_setup();
  mtss_uni(14, b, sizeof b, 0);
  return moqtrun_test_close_code();
}

/* A (alice, alias 1) sends datagram b. */
static u64 mtcc_dg(const u8* b, usz n) {
  mtrq_setup();
  wired_moqt_on_datagram(&mtst_hub, SESS_A, wired_span_of(b, n));
  return moqtrun_test_close_code();
}

/* 11.2.1: datagram Type 0x40 (outside 0b00X0XXXX): INVALID_STREAM_HEADER. */
static u64 mtcc_dg_type(void) {
  static const u8 b[] = {0x40, 0x01, 0x00, 0x00, 0x00, 'x'};
  return mtcc_dg(b, sizeof b);
}

/* 11.2.1: PROPERTIES with a Properties Length of 0: MALFORMED_OBJECT. */
static u64 mtcc_dg_props0(void) {
  static const u8 b[] = {0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 'x'};
  return mtcc_dg(b, sizeof b);
}

/* 11.2.1: STATUS and PROPERTIES with a non-Normal Status:
 * INVALID_OBJECT_STATUS. */
static u64 mtcc_dg_status_props(void) {
  static const u8 b[] = {0x21, 0x01, 0x00, 0x00, 0x00, 0x02, 0x04, 0x01, 0x03};
  return mtcc_dg(b, sizeof b);
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
    {mtcc_psn_from_subscriber, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_ROLE_VIOLATION},
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
    {mtcc_sg_status, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_OBJECT_STATUS},
    {mtcc_sg_props_eog, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_OBJECT_STATUS},
    {mtcc_sg_id_wrap, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_DELTA_ENCODING_OVERFLOW},
    {mtcc_sg_fin_torn, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_TRUNCATED_OBJECT},
    {mtcc_uni_unknown, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_STREAM_HEADER},
    {mtcc_dg_type, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_STREAM_HEADER},
    {mtcc_dg_props0, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_MALFORMED_OBJECT},
    {mtcc_dg_status_props, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_OBJECT_STATUS},
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

/* draft-23 2.4.1: "If an endpoint receives a Track Name with a length of
 * 0, it MUST close the session with a PROTOCOL_VIOLATION" -- on every
 * request that carries one (Request ID 0, namespace "c", Track Name
 * Length 0, then the rest). draft-18..22 allowed an empty Track Name. */
static u64 mtcc_name_empty(u64 type) {
  static const u8 b[] = {0x00, 0x01, 0x01, 'c', 0x00, 0x00};
  return mtcc_req(type, b, sizeof b);
}

static u64 mtcc_subscribe_name_empty(void) {
  return mtcc_name_empty(MOQCTL_T_SUBSCRIBE);
}

static u64 mtcc_tstat_name_empty(void) {
  return mtcc_name_empty(MOQTSTAT_T_TRACK_STATUS);
}

/* PUBLISH: Track Alias 1 and no Parameters after the empty name. */
static u64 mtcc_publish_name_empty(void) {
  static const u8 b[] = {0x00, 0x01, 0x01, 'c', 0x00, 0x01, 0x00};
  return mtcc_req(MOQCTL_T_PUBLISH, b, sizeof b);
}

/* draft-23 6.5 no longer singles out ".session" with an empty Track
 * Name (draft-22 6.5: DOES_NOT_EXIST); 2.4.1 closes the session first.
 * Before draft-23 it is still refused DOES_NOT_EXIST, no close. */
static u64 mtcc_session_name_empty(void) {
  static const u8 b[] = {0x00, 0x01, 0x08, '.', 's',  'e', 's',
                         's',  'i',  'o',  'n', 0x00, 0x00};
  u64             got = mtcc_req(MOQCTL_T_SUBSCRIBE, b, sizeof b);
  CHECK(got != ~(u64)0 || mtrq_err_on(MTRQ_S1) == MOQCTL_ERR_DOES_NOT_EXIST);
  return got;
}

static u64 (*const mtcc_name_cases[])(void) = {
    mtcc_subscribe_name_empty, mtcc_tstat_name_empty, mtcc_publish_name_empty,
    mtcc_session_name_empty};

/* The close an empty Track Name earns in the harness draft: none before
 * draft-23. */
static u64 mtcc_name_want(void) {
  return (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_TRACK_NAME_NONEMPTY)
             ? WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION
             : ~(u64)0;
}

static void mtcc_name_all(void) {
  for (usz i = 0; i < sizeof mtcc_name_cases / sizeof mtcc_name_cases[0]; i++) {
    u64 got = mtcc_name_cases[i]();
    CHECK(got == mtcc_name_want());
    if (got != mtcc_name_want()) {
      printf(
          "  ^ empty name case %u got 0x%llx\n", (unsigned)i,
          (unsigned long long)got);
    }
  }
}

/* FETCH: the draft-22 body (Request ID, Full Track Name, Parameters). */
static void mtcc_fetch_name_empty(void) {
  CHECK(mtcc_name_empty(MOQFETCH_T_FETCH) == mtcc_name_want());
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
  moqtrun_test_vers(0, 0, mtcc_name_all);
  moqtrun_test_vers(MOQVER_CAP_FETCH_BODY_V22, 0, mtcc_fetch_name_empty);
}
