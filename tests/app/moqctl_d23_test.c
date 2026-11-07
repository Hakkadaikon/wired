/* draft-ietf-moq-transport-23 Message Parameters against draft-22: the
 * renamed and rescoped ones (9.19). */

/* One uint8 Parameter type = v as a Parameters block, decoded under ver
 * and ctx into *out. */
static int mqd23_take_u8(int ver, u64 type, u8 v, u32 ctx, moqctl_params* out) {
  static u8 buf[8]; /* out views into it */
  usz       n = 0, off = 0;
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &n, 1));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &n, type));
  buf[n++] = v;
  return moqctl_params_take(ver, wired_span_of(buf, n), &off, ctx, out);
}

static int mqd23_sub(int ver, u64 type, u8 v, moqctl_params* out) {
  return mqd23_take_u8(ver, type, v, MOQCTL_PCTX_SUBSCRIBE, out);
}

/* 9.19.18: PAUSED (0x11) 0 / 1 decodes as FORWARD 1 / 0, one name for a
 * subscription's state on every draft; 2 is INVALID_PARAMETER, so is
 * PAUSED outside its scope, and FORWARD (0x10) is unregistered in
 * draft-23. Draft-22 knows FORWARD only. */
static void test_moqctl_d23_paused_take(void) {
  moqctl_params out;
  CHECK(mqd23_sub(MOQVER_D23, MOQCTL_PARAM_PAUSED, 1, &out) == MOQCTL_OK);
  CHECK(out.n == 1 && out.items[0].type == MOQCTL_PARAM_FORWARD);
  CHECK(out.items[0].u8v == 0);
  CHECK(mqd23_sub(MOQVER_D23, MOQCTL_PARAM_PAUSED, 0, &out) == MOQCTL_OK);
  CHECK(out.items[0].type == MOQCTL_PARAM_FORWARD && out.items[0].u8v == 1);
  CHECK(mqd23_sub(MOQVER_D23, MOQCTL_PARAM_PAUSED, 2, &out) == MOQCTL_R_PARAM);
  CHECK(mqd23_sub(MOQVER_D23, MOQCTL_PARAM_FORWARD, 1, &out) == MOQCTL_R_PARAM);
  CHECK(
      mqd23_take_u8(
          MOQVER_D23, MOQCTL_PARAM_PAUSED, 0, MOQCTL_PCTX_PUBLISH_OK, &out) ==
      MOQCTL_R_PARAM);
  CHECK(mqd23_sub(MOQVER_D22, MOQCTL_PARAM_PAUSED, 0, &out) == MOQCTL_R_PARAM);
  CHECK(mqd23_sub(MOQVER_D22, MOQCTL_PARAM_FORWARD, 0, &out) == MOQCTL_OK);
  CHECK(out.items[0].type == MOQCTL_PARAM_FORWARD && out.items[0].u8v == 0);
}

/* FORWARD fwd then GROUP_ORDER 2, readied for ver and encoded into buf;
 * its length. */
static usz mqd23_put_fwd(int ver, u8 fwd, u8* buf, usz cap) {
  moqctl_params p = {0};
  usz           n = 0;
  p.items[0]      = (moqctl_param){.type = MOQCTL_PARAM_FORWARD, .u8v = fwd};
  p.items[1]      = (moqctl_param){.type = MOQCTL_PARAM_GROUP_ORDER, .u8v = 2};
  p.n             = 2;
  moqctl_params_out(ver, &p);
  CHECK(moqctl_params_put(wired_mspan_of(buf, cap), &n, &p));
  return n;
}

/* 9.19.18 on the way out: toward draft-23 FORWARD 1 goes as PAUSED 0
 * (count 2, delta 0x11, 0, delta 0x22 - 0x11, 2); draft-22 keeps FORWARD
 * (delta 0x10, 1, delta 0x12, 2). */
static void test_moqctl_d23_paused_put(void) {
  static const u8 d23[] = {0x02, 0x11, 0x00, 0x11, 0x02};
  static const u8 d22[] = {0x02, 0x10, 0x01, 0x12, 0x02};
  u8              buf[8];
  CHECK(mqd23_put_fwd(MOQVER_D23, 1, buf, sizeof buf) == sizeof d23);
  CHECK(ct_diffn(buf, d23, sizeof d23) == 0);
  CHECK(mqd23_put_fwd(MOQVER_D22, 1, buf, sizeof buf) == sizeof d22);
  CHECK(ct_diffn(buf, d22, sizeof d22) == 0);
}

void test_moqctl_d23(void) {
  test_moqctl_d23_paused_take();
  test_moqctl_d23_paused_put();
}
