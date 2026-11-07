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

/* One Parameter type with raw value bytes v[0..n) under ver and ctx. */
static int mqd23_take_raw(
    int ver, u64 type, const u8* v, usz n, u32 ctx, moqctl_params* out) {
  static u8 buf[32]; /* out views into it */
  usz       len = 0, off = 0;
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &len, 1));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &len, type));
  for (usz i = 0; i < n; i++) {
    buf[len++] = v[i];
  }
  return moqctl_params_take(ver, wired_span_of(buf, len), &off, ctx, out);
}

/* type with value v[0..n) is admitted in ctx by draft-23 (in23) and by
 * draft-22 (in22); anything else is INVALID_PARAMETER. */
static int mqd23_scope(
    u64 type, const u8* v, usz n, u32 ctx, int in23, int in22) {
  moqctl_params out;
  int           r23 = mqd23_take_raw(MOQVER_D23, type, v, n, ctx, &out);
  int           r22 = mqd23_take_raw(MOQVER_D22, type, v, n, ctx, &out);
  return r23 == (in23 ? MOQCTL_OK : MOQCTL_R_PARAM) &&
         r22 == (in22 ? MOQCTL_OK : MOQCTL_R_PARAM);
}

/* draft-23 9.17 / 9.19.3-4 / 9.19.7 / 9.19.9 / 9.19.15: SUBSCRIBE_TRACKS
 * takes the delivery timeouts, SUBSCRIBER_PRIORITY, LOCATION_FILTER and
 * FILL_PARAMETERS (here a count-0 value); PUBLISH takes FILL_PARAMETERS
 * (9.8); 9.19.16 lets EXPIRES into TRACK_STATUS_OK; REQUEST_UPDATE of a
 * FETCH takes no delivery timeout (9.5). Draft-22 the other way round. */
static void test_moqctl_d23_scope(void) {
  static const u8 vi5[]  = {0x05};
  static const u8 none[] = {0x00}; /* LOCATION_FILTER Type 0x00; count 0 */
  const u32       st     = MOQCTL_PCTX_SUBSCRIBE_TRACKS;
  CHECK(mqd23_scope(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, vi5, 1, st, 1, 0));
  CHECK(mqd23_scope(MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT, vi5, 1, st, 1, 0));
  CHECK(mqd23_scope(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, vi5, 1, st, 1, 0));
  CHECK(mqd23_scope(MOQCTL_PARAM_LOCATION_FILTER, none, 1, st, 1, 0));
  CHECK(mqd23_scope(MOQCTL_PARAM_FILL_PARAMETERS, none, 1, st, 1, 0));
  CHECK(mqd23_scope(
      MOQCTL_PARAM_FILL_PARAMETERS, none, 1, MOQCTL_PCTX_PUBLISH, 1, 0));
  CHECK(mqd23_scope(
      MOQCTL_PARAM_EXPIRES, vi5, 1, MOQCTL_PCTX_TRACK_STATUS_OK, 1, 0));
  CHECK(mqd23_scope(
      MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT, vi5, 1, MOQCTL_PCTX_UPDATE_FETCH, 0,
      1));
}

void test_moqctl_d23(void) {
  test_moqctl_d23_paused_take();
  test_moqctl_d23_paused_put();
  test_moqctl_d23_scope();
}
