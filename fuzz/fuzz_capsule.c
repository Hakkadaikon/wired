/* libFuzzer harness for the HTTP capsule codec (RFC 9297 3), the
 * WebTransport capsules layered on it (draft-ietf-webtrans-http3-15
 * 4.2/5.6), HTTP/3 frame + SETTINGS parsing (RFC 9114 7.2/7.2.4), and the
 * QPACK encoder/decoder-stream instruction decoders (RFC 9204 4.3/4.4).
 * Hosted build only — mirrors tests/run.c's unity-include style, but this
 * file itself may use the standard library since it lives outside src/.
 *
 * All of these are length-prefixed varint wire formats over untrusted
 * stream bytes, so one raw input plausibly exercises each decoder; every
 * decoder validates its own type/length fields and rejects cheaply. */
#include <stddef.h>
#include <stdint.h>

#include "app/http3/core/capsule/capsule.c"
#include "app/http3/core/h3/frame.c"
#include "app/http3/core/h3/settings_check.c"
#include "app/http3/core/h3/settings_dup.c"
#include "app/qpack/qpack/dyntable.c"
#include "app/qpack/qpack/instruction.c"
#include "app/qpack/qpack/integer.c"
#include "app/qpack/qpackdyn/enc_stream.c"
#include "app/webtransport/capsule/wtcapsule/wtcapsule.c"
#include "common/bytes/varint/varint.c"

/* RFC 9297 3: walk every complete capsule, then the WT-typed decoders at
 * the same cursor discipline (wrong type leaves *at unconsumed). */
static void fuzz_capsules(wired_span in) {
  usz        at = 0;
  u64        type;
  wired_span value;
  while (capsule_decode(in, &at, &type, &value)) {}
  capsule_fin_truncated(in, at, 1);

  usz        wt = 0;
  u32        code;
  wired_span msg;
  u64        v;
  wired_wtcapsule_decode_close(in, &wt, &code, &msg);
  wtcapsule_decode_drain(in, &wt);
  wtcapsule_decode_max_streams(in, &wt, 0, &v);
  wtcapsule_decode_max_streams(in, &wt, 1, &v);
  wtcapsule_decode_streams_blocked(in, &wt, 0, &v);
  wtcapsule_decode_streams_blocked(in, &wt, 1, &v);
  wtcapsule_decode_max_data(in, &wt, &v);
  wtcapsule_decode_data_blocked(in, &wt, &v);
}

/* RFC 9114 7.2: generic frame decode, the fixed-payload getters, and a
 * SETTINGS payload walk with the duplicate/permission checks. */
static void fuzz_h3(wired_span in) {
  h3_frame f;
  h3_frame_get(in, &f);

  u64 id;
  h3_cancel_push_get(in.p, in.n, &id);
  h3_goaway_get(in.p, in.n, &id);
  h3_max_push_id_get(in.p, in.n, &id);

  h3_settings s;
  if (!h3_settings_get(in.p, in.n, &s)) return;
  h3_settings_seen seen;
  h3_settings_seen_init(&seen);
  for (usz i = 0; i < s.n; i++) {
    h3_setting_allowed(s.pairs[i].id);
    h3_setting_h3_datagram_value_ok(s.pairs[i].id, s.pairs[i].value);
    h3_settings_mark(&seen, s.pairs[i].id);
  }
}

/* RFC 9204 4.3/4.4: instruction decoders, then Set Dynamic Table Capacity
 * applied against a live dynamic table. */
static void fuzz_qpack(wired_span in) {
  qpack_enc_kind ek;
  qpack_dec_kind dk;
  u64            value;
  qpack_enc_instr_decode(in, &ek, &value);
  qpack_dec_instr_decode(in, &dk, &value);

  qpack_dyn table;
  qpack_dyn_init(&table, 4096);
  u16 err = 0;
  qdyn_enc_apply_capacity(in, &table, 4096, &err);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  wired_span in = wired_span_of((const u8 *)data, (usz)size);
  fuzz_capsules(in);
  fuzz_h3(in);
  fuzz_qpack(in);
  return 0;
}
