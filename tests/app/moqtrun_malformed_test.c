/* The hub's session close for each malformed control field, driven end to
 * end through wired_moqt_on_stream_data under every draft: draft-18..22
 * close PROTOCOL_VIOLATION, draft-23 12.2 names the cause's code. Each
 * limit has its in-range twin, which closes nothing, so the close is the
 * limit's own. Shares the fixtures of moqtrun_test.c, moqtrun_sub_test.c
 * (mtrq_setup, mtrq_raw), moqtrun_done_test.c (mtdn_setup, MTDN_PUB),
 * moqtrun_drain_test.c (mtdr_ctl), moqtrun_sess_test.c (mtss_uni),
 * moqtrun_cc_test.c (mtcc_case) and moqtrun_upsub_test.c (mups_*) -- same
 * unity TU. */

#define MTMF_NONE (~(u64)0)

/* mtrq_raw with a larger buffer: Type + 16-bit Length + body on s's
 * stream sid, body past MTST_MSG_MAX (a New Session URI of 8193 bytes). */
static void mtmf_raw(
    wired_wt_session* s, u64 sid, u64 type, const u8* body, usz n) {
  static u8 buf[8300];
  usz       off = 0;
  CHECK(n + 12 <= sizeof buf);
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, type));
  buf[off++] = (u8)(n >> 8);
  buf[off++] = (u8)n;
  bytes_memcpy(buf + off, body, n);
  mt_feed(&mtst_hub, s, sid, wired_span_of(buf, off + n), 0);
}

/* ===== Reason Phrase: draft-18/19 1.4.4, draft-22/23 8.5 ===== */

/* A's PUBLISH_DONE (TRACK_ENDED, Stream Count 0) with a Reason Phrase of
 * len bytes (two-byte vi64 Length). */
static u64 mtmf_reason(usz len) {
  static u8 b[8 + 1025];
  b[0] = (u8)MOQCTL_DONE_TRACK_ENDED;
  b[1] = 0x00;
  b[2] = (u8)(0x80 | (len >> 8));
  b[3] = (u8)len;
  for (usz i = 0; i < len; i++) {
    b[4 + i] = 'r';
  }
  mtdn_setup();
  mtrq_raw(SESS_A, MTDN_PUB, MOQCTL_T_PUBLISH_DONE, b, 4 + len);
  return moqtrun_test_close_code();
}

static u64 mtmf_reason_1024(void) { return mtmf_reason(1024); }

static u64 mtmf_reason_1025(void) { return mtmf_reason(1025); }

/* ===== Full Track Name: draft-18/19 2.4.1, draft-22/23 8.7 ===== */

/* B SUBSCRIBEs to {one field of field bytes} / "x" (no Parameters). */
static u64 mtmf_ftn(usz field) {
  static u8 b[4200];
  usz       n = 0;
  b[n++]      = 0x00; /* Request ID */
  b[n++]      = 0x01; /* one namespace field */
  b[n++]      = (u8)(0x80 | (field >> 8));
  b[n++]      = (u8)field;
  for (usz i = 0; i < field; i++) {
    b[n++] = 'n';
  }
  b[n++] = 0x01;
  b[n++] = 'x';
  b[n++] = 0x00;
  mtrq_setup();
  mtmf_raw(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE, b, n);
  return moqtrun_test_close_code();
}

static u64 mtmf_ftn_4096(void) { return mtmf_ftn(4095); }

static u64 mtmf_ftn_4097(void) { return mtmf_ftn(4096); }

/* ===== GOAWAY New Session URI: draft-18/19 10.4, draft-22/23 9.2 ===== */

/* B's control-stream GOAWAY with a New Session URI of len bytes, Timeout
 * 0 (and, on draft-18, Request ID 1). A URI sent to the server is itself a
 * ROLE_VIOLATION (draft-23 9.2), so the in-range twin still closes, but
 * not FIELD_LENGTH_EXCEEDED. */
static u64 mtmf_goaway(usz len) {
  static u8 b[8 + 8193];
  b[0] = (u8)(0x80 | (len >> 8));
  b[1] = (u8)len;
  for (usz i = 0; i < len; i++) {
    b[2 + i] = 'u';
  }
  b[2 + len] = 0x00; /* Timeout */
  b[3 + len] = 0x01; /* draft-18's Request ID */
  usz n      = 3 + len;
  n += (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_GOAWAY_REQID) != 0;
  mtrq_setup();
  mtmf_raw(SESS_B, mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY, b, n);
  return moqtrun_test_close_code();
}

static u64 mtmf_goaway_8192(void) { return mtmf_goaway(8192); }

static u64 mtmf_goaway_8193(void) { return mtmf_goaway(8193); }

/* B's GOAWAY with no URI, Timeout 0 (draft-18: Request ID 1), then extra
 * bytes its Length counts. */
static u64 mtmf_goaway_tail(usz extra) {
  u8  b[8] = {0x00, 0x00, 0x01, 0x00, 0x00};
  usz n    = 2 + extra;
  n += (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_GOAWAY_REQID) != 0;
  mtrq_setup();
  mtrq_raw(SESS_B, mtdr_ctl(SESS_B), MOQCTL_T_GOAWAY, b, n);
  return moqtrun_test_close_code();
}

static u64 mtmf_goaway_exact(void) { return mtmf_goaway_tail(0); }

static u64 mtmf_goaway_extra(void) { return mtmf_goaway_tail(1); }

/* ===== Message Parameters: draft-18/19 10.2, draft-22 9.20, draft-23
 * 9.19 ===== */

/* B SUBSCRIBEs to {"c"} / "x" with the Parameters bytes p (Number of
 * Parameters first). */
static u64 mtmf_params(const u8* p, usz n) {
  static const u8 head[] = {0x00, 0x01, 0x01, 'c', 0x01, 'x'};
  u8              b[64];
  bytes_memcpy(b, head, sizeof head);
  bytes_memcpy(b + sizeof head, p, n);
  mtrq_setup();
  mtrq_raw(SESS_B, MTRQ_S1, MOQCTL_T_SUBSCRIBE, b, sizeof head + n);
  return moqtrun_test_close_code();
}

/* SUBSCRIBER_PRIORITY (0x20) = 1, alone. */
static u64 mtmf_param_one(void) {
  static const u8 p[] = {0x01, 0x20, 0x01};
  return mtmf_params(p, sizeof p);
}

/* SUBSCRIBER_PRIORITY, then a Delta Type of 2^64-1: the Type passes
 * 2^64-1. */
static u64 mtmf_param_delta(void) {
  static const u8 p[] = {0x02, 0x20, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
  return mtmf_params(p, sizeof p);
}

/* SUBSCRIBER_PRIORITY twice (Delta Type 0). */
static u64 mtmf_param_dup(void) {
  static const u8 p[] = {0x02, 0x20, 0x01, 0x00, 0x01};
  return mtmf_params(p, sizeof p);
}

/* ===== Location Filter: draft-18/19 5.1.2, draft-22 9.20.9, draft-23
 * 9.19.9 ===== */

/* 1 iff the harness draft spells LOCATION_FILTER typed, with no Length
 * (draft-22 9.20.9, draft-23 9.19.9). */
static int mtmf_typed(void) {
  return (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_LOCFILTER_TYPED) != 0;
}

/* LOCATION_FILTER (0x21) value v (n bytes): after Length n in
 * draft-18/19, bare once typed. */
static u64 mtmf_filter(const u8* v, usz n) {
  u8  p[32] = {0x01, 0x21, (u8)n};
  usz at    = mtmf_typed() ? 2 : 3;
  bytes_memcpy(p + at, v, n);
  return mtmf_params(p, at + n);
}

/* An AbsoluteRange from {1, 0} with End Group Delta FF..FF last (9
 * bytes): Type 0x04 in draft-18/19, 0x03 (StartGroup, StartObject,
 * EndGroupDelta) once typed. */
static u64 mtmf_range(u8 last) {
  u8 v[] = {0x04, 0x01, 0x00, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, last};
  v[0]   = mtmf_typed() ? 0x03 : 0x04;
  return mtmf_filter(v, sizeof v);
}

/* End Group 1 + (2^64-2) = 2^64-1: in range. */
static u64 mtmf_range_max(void) { return mtmf_range(0xFE); }

/* End Group 1 + (2^64-1) passes 2^64-1. */
static u64 mtmf_range_over(void) { return mtmf_range(0xFF); }

/* Location Filter Type 0x07, defined in no draft. */
static u64 mtmf_filter_unknown(void) {
  static const u8 v[] = {0x07};
  return mtmf_filter(v, sizeof v);
}

/* ===== Message Length: draft-18/19 10, draft-22/23 9 ===== */

/* A whole SUBSCRIBE plus one byte its Length counts. */
static u64 mtmf_len_extra(void) {
  static const u8 p[] = {0x00, 0x00};
  return mtmf_params(p, sizeof p);
}

/* The same SUBSCRIBE without the extra byte. */
static u64 mtmf_len_exact(void) {
  static const u8 p[] = {0x00};
  return mtmf_params(p, sizeof p);
}

/* ===== Stream header: draft-18/19 11.4.2, draft-22/23 11.4.2 ===== */

/* A's uni stream of SUBGROUP_HEADER Type 0x16: SUBGROUP_ID_MODE 0b11. */
static u64 mtmf_sg_mode3(void) {
  static const u8 b[] = {0x16, 0x01, 0x00, 0x00, 0x00};
  mtrq_setup();
  mtss_uni(14, b, sizeof b, 0);
  return moqtrun_test_close_code();
}

/* ===== Messages A sends on the hub's upstream SUBSCRIBE stream ===== */

/* B's SUBSCRIBE went upstream to A; A answers type with body b (n bytes,
 * plus extra trailing bytes its Length counts) there. */
static u64 mtmf_up(u64 type, int ok, u8* b, usz n, usz extra) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  u64 sid = (u64)mups_up_sid();
  if (ok) {
    mups_ok(sid);
  }
  for (usz i = 0; i < extra; i++) {
    b[n + i] = 0x00;
  }
  mtrq_raw(SESS_A, sid, type, b, n + extra);
  return moqtrun_test_close_code();
}

/* REQUEST_ERROR DOES_NOT_EXIST, Retry Interval 0, empty Reason Phrase
 * (draft-18/19 10.6, draft-22 9.4); draft-23 9.4's Error Details run to
 * the end, so the extra byte is a cut Key-Value-Pair there (8.3). */
static u64 mtmf_reqerr(usz extra) {
  u8 b[8] = {0x00, 0x00, 0x00};
  b[0]    = (u8)moqctl_request_error_for(
      g_moqtrun_test_ver, MOQCTL_ERR_DOES_NOT_EXIST);
  return mtmf_up(MOQCTL_T_REQUEST_ERROR, 0, b, 3, extra);
}

static u64 mtmf_reqerr_exact(void) { return mtmf_reqerr(0); }

static u64 mtmf_reqerr_extra(void) { return mtmf_reqerr(1); }

/* Upstream PUBLISH_DONE TRACK_ENDED, Stream Count 0, empty Reason
 * (moqtrun_up_on_done). */
static u64 mtmf_up_done(usz extra) {
  u8 b[8] = {(u8)MOQCTL_DONE_TRACK_ENDED, 0x00, 0x00};
  return mtmf_up(MOQCTL_T_PUBLISH_DONE, 1, b, 3, extra);
}

static u64 mtmf_up_done_exact(void) { return mtmf_up_done(0); }

static u64 mtmf_up_done_extra(void) { return mtmf_up_done(1); }

static const mtcc_case mtmf_cases[] = {
    {mtmf_reqerr_exact, MTMF_NONE, MTMF_NONE},
    {mtmf_reqerr_extra, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE},
    {mtmf_up_done_exact, MTMF_NONE, MTMF_NONE},
    {mtmf_up_done_extra, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE},
    {mtmf_sg_mode3, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_STREAM_HEADER},
    {mtmf_reason_1024, MTMF_NONE, MTMF_NONE},
    {mtmf_reason_1025, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_FIELD_LENGTH_EXCEEDED},
    {mtmf_ftn_4096, MTMF_NONE, MTMF_NONE},
    {mtmf_ftn_4097, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_FIELD_LENGTH_EXCEEDED},
    {mtmf_goaway_8192, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_ROLE_VIOLATION},
    {mtmf_goaway_8193, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_FIELD_LENGTH_EXCEEDED},
    {mtmf_param_one, MTMF_NONE, MTMF_NONE},
    {mtmf_param_delta, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_DELTA_ENCODING_OVERFLOW},
    {mtmf_param_dup, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_PARAMETER},
    {mtmf_range_max, MTMF_NONE, MTMF_NONE},
    {mtmf_range_over, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_DELTA_ENCODING_OVERFLOW},
    {mtmf_filter_unknown, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_PARAMETER},
    {mtmf_goaway_exact, MTMF_NONE, MTMF_NONE},
    {mtmf_goaway_extra, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE},
    {mtmf_len_exact, MTMF_NONE, MTMF_NONE},
    {mtmf_len_extra, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE},
};

static void mtmf_all_cases(void) {
  int d23 = (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_CLOSE_CODES23) != 0;
  for (usz i = 0; i < sizeof mtmf_cases / sizeof mtmf_cases[0]; i++) {
    const mtcc_case* c    = &mtmf_cases[i];
    u64              got  = c->run();
    u64              want = d23 ? c->d23 : c->before;
    CHECK(got == want);
    if (got != want) {
      printf(
          "  ^ malformed case %u got 0x%llx\n", (unsigned)i,
          (unsigned long long)got);
    }
  }
}

/* draft-23 9.2: a GOAWAY on the hub's upstream SUBSCRIBE stream (URI
 * empty, Timeout 0) moves the request (moqtrun_goaway_moves); one more
 * byte inside its Length is MALFORMED_MESSAGE (9). */
static void mtmf_req_goaway(void) {
  u8 b[4] = {0x00, 0x00};
  CHECK(mtmf_up(MOQCTL_T_GOAWAY, 0, b, 2, 0) == MTMF_NONE);
  CHECK(
      mtmf_up(MOQCTL_T_GOAWAY, 0, b, 2, 1) ==
      WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE);
}

void test_moqtrun_malformed(void) {
  moqtrun_test_allver(mtmf_all_cases);
  moqtrun_test_vers(MOQVER_CAP_REQ_GOAWAY23, 0, mtmf_req_goaway);
}
