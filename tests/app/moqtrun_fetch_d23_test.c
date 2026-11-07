/* draft-ietf-moq-transport-23 FETCH as the hub serves it, against
 * draft-22 on the same scenario: the fetch stream encoding (11.4). Every
 * scenario runs once per draft with the draft-22 FETCH layout. */

/* 11.4.1.1: consecutive Objects of a Group leave the Object ID Delta out
 * (a present one would mean prior + Delta + 2 on draft-23), a new Group
 * carries Group ID Delta; the stream decodes under B's own draft. */
static void test_moqtrun_fetch_d23_stream(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mf_read() && mf_n == 3);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 0, 1, 1));
  CHECK(mf_is_obj(2, 1, 0, 1));
}

/* The FETCH response on B's last request stream, decoded independently
 * of moqfetch: its Type; for a draft-23 REQUEST_OK *largest is 1 and *end
 * the LARGEST_OBJECT when one came, for a FETCH_OK *end its End
 * Location; *code a REQUEST_ERROR's code. */
static u64 mfd23_reply(moqctl_loc* end, int* largest, u64* code) {
  moqctl_request_ok ok;
  usz               off = 0;
  u64               t   = mf_reply(code, end);
  *largest              = 0;
  if (t != MOQCTL_T_REQUEST_OK) {
    return t;
  }
  for (usz i = g_n_calls; i-- > 0;) {
    const moqtrun_test_call* c = &g_calls[i];
    u64                      type;
    wired_span               body;
    if (c->kind != 12 || c->stream_id != mf_req_sid) {
      continue;
    }
    mt_peek_type(wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    off = 0;
    CHECK(moqctl_request_ok_take(mtst_ver(c->s), body, &off, &ok) == MOQCTL_OK);
    const moqctl_param* lo =
        moqctl_params_find(&ok.params, MOQCTL_PARAM_LARGEST_OBJECT);
    *largest = lo != 0;
    if (lo) {
      *end = lo->loc;
    }
    break;
  }
  return t;
}

static int mfd23_is23(void) {
  return (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_FETCH_REQUEST_OK) != 0;
}

/* B's draft's answer to a FETCH served from the cache ending at {g, o}:
 * draft-23 3.2 / 9.3 a REQUEST_OK with LARGEST_OBJECT {g, o} iff largest
 * (Largest Object is within the range), else draft-22 9.12's FETCH_OK
 * with that inclusive End Location. */
static int mfd23_ok_is(u64 g, u64 o, int largest) {
  moqctl_loc end  = {~0ULL, ~0ULL};
  int        has  = 0;
  u64        code = 0;
  u64        t    = mfd23_reply(&end, &has, &code);
  if (!mfd23_is23()) {
    return t == MOQFETCH_T_FETCH_OK && mf_loc_eq(end, g, o);
  }
  return t == MOQCTL_T_REQUEST_OK && has == largest &&
         (!largest || mf_loc_eq(end, g, o));
}

/* draft-23 3.2: the response ends at Largest Object when it is in the
 * requested range and FETCH_OK carries LARGEST_OBJECT; a range ending
 * before it carries none. */
static void test_moqtrun_fetch_d23_ok(void) {
  moqctl_rangeloc obj00 = mf_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_OBJ, 0, 0);
  moqctl_rangeloc to10  = mf_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_OBJ, 1, 0);
  moqctl_rangeloc past  = mf_rl(MOQCTL_RSK_ABS, 0, 1, MOQCTL_REK_OBJ, 7, 0);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mfd23_ok_is(1, 0, 1));
  mf_fetch_v(g_moqtrun_test_ver, &obj00);
  CHECK(mfd23_ok_is(0, 0, 0));
  mf_fetch_v(g_moqtrun_test_ver, &to10);
  CHECK(mfd23_ok_is(1, 0, 1));
  mf_fetch_v(g_moqtrun_test_ver, &past);
  CHECK(mfd23_ok_is(1, 0, 1));
}

/* draft-23 3.2: a relative Location filter (9.19.9 Type 0x01) on FETCH
 * is INVALID_RANGE; draft-22 serves it from the Largest Group back. */
static void test_moqtrun_fetch_d23_relative(void) {
  moqctl_rangeloc cur =
      mf_rl(MOQCTL_RSK_REL_GROUP, 1, 0, MOQCTL_REK_UNBOUNDED, 0, 0);
  moqctl_loc end  = {0, 0};
  int        has  = 0;
  u64        code = 0;
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  mf_fetch_v(g_moqtrun_test_ver, &cur);
  if (mfd23_is23()) {
    CHECK(mfd23_reply(&end, &has, &code) == MOQCTL_T_REQUEST_ERROR);
    CHECK(code == MOQCTL_ERR_INVALID_RANGE);
    return;
  }
  CHECK(mfd23_ok_is(1, 0, 1));
}

static void mtall_fetch_d23(void) {
  test_moqtrun_fetch_d23_stream();
  test_moqtrun_fetch_d23_ok();
  test_moqtrun_fetch_d23_relative();
}

void test_moqtrun_fetch_d23(void) {
  moqtrun_test_vers(MOQVER_CAP_FETCH_BODY_V22, 0, mtall_fetch_d23);
}
