#include "test.h"

static int h3f_bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

/* Generic DATA/HEADERS frames round-trip type + length + opaque payload. */
static void test_h3frame_generic(void) {
  u8         body[] = {0xde, 0xad, 0xbe, 0xef};
  u8         buf[16];
  wired_obuf ob = {buf, sizeof buf, 0};
  usz w = h3_frame_put(&ob, H3_FRAME_DATA, wired_span_of(body, sizeof body));
  CHECK(w == 2 + sizeof(body) && buf[0] == H3_FRAME_DATA);

  h3_frame f;
  usz      r = h3_frame_get(wired_span_of(buf, w), &f);
  CHECK(r == w && f.type == H3_FRAME_DATA && f.payload_len == sizeof(body));
  CHECK(h3f_bytes_eq(f.payload, body, sizeof(body)));

  /* HEADERS carries an opaque (QPACK) block the same way. */
  u8  hb[] = {0x01, 0x02, 0x03};
  usz hw   = h3_frame_put(&ob, H3_FRAME_HEADERS, wired_span_of(hb, sizeof hb));
  usz hr   = h3_frame_get(wired_span_of(buf, hw), &f);
  CHECK(
      hr == hw && f.type == H3_FRAME_HEADERS &&
      h3f_bytes_eq(f.payload, hb, sizeof(hb)));

  /* truncated: Length claims 4 bytes but only 3 are present */
  CHECK(h3_frame_get(wired_span_of(buf, hw - 1), &f) == 0);
}

/* GOAWAY carries a Stream/Push ID. */
static void test_h3frame_push_ids(void) {
  u8  buf[16];
  u64 v;
  usz gw = h3_goaway_put(buf, sizeof(buf), 40);
  CHECK(gw != 0 && buf[0] == H3_FRAME_GOAWAY);
  CHECK(h3_goaway_get(buf, gw, &v) == gw && v == 40);
  CHECK(h3_goaway_get(buf, gw - 1, &v) == 0);

  /* type mismatch is rejected (SETTINGS-typed bytes decoded as GOAWAY) */
  buf[0] = H3_FRAME_SETTINGS;
  CHECK(h3_goaway_get(buf, gw, &v) == 0);

  /* no room for the Length, then for the value; an empty input has no head */
  CHECK(h3_goaway_put(buf, 1, 40) == 0);
  CHECK(h3_goaway_put(buf, 2, 40) == 0);
  CHECK(h3_goaway_get(buf, 0, &v) == 0);
}

/* SETTINGS round-trips multiple (id, value) pairs including the field size. */
static void test_h3frame_settings(void) {
  h3_settings in    = {.n = 2};
  in.pairs[0].id    = H3_SETTINGS_MAX_FIELD_SECTION_SIZE;
  in.pairs[0].value = 0x4000;
  in.pairs[1].id    = 0x21;
  in.pairs[1].value = 99;
  u8  buf[32];
  usz w = h3_settings_put(buf, sizeof(buf), &in);
  CHECK(w != 0 && buf[0] == H3_FRAME_SETTINGS);

  h3_settings out;
  usz         r = h3_settings_get(buf, w, &out);
  CHECK(r == w && out.n == 2);
  CHECK(out.pairs[0].id == H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
  CHECK(out.pairs[0].value == 0x4000);
  CHECK(out.pairs[1].id == 0x21 && out.pairs[1].value == 99);

  /* truncated: a pair's value varint is cut off */
  CHECK(h3_settings_get(buf, w - 1, &out) == 0);

  /* empty SETTINGS is valid and round-trips to zero pairs */
  h3_settings empty = {.n = 0};
  usz         ew    = h3_settings_put(buf, sizeof(buf), &empty);
  CHECK(h3_settings_get(buf, ew, &out) == ew && out.n == 0);
}

/* Pinning: a frame claiming a Length that runs past the actual input span
 * must be rejected, never sized into an out-of-bounds payload view
 * (V-0422/GHSA-g754-hx8w-x2g6). */
static void test_h3frame_get_length_exceeds_buffer_rejected(void) {
  u8         buf[16];
  wired_obuf ob      = {buf, sizeof buf, 0};
  u8         body[4] = {1, 2, 3, 4};
  usz w = h3_frame_put(&ob, H3_FRAME_DATA, wired_span_of(body, sizeof body));

  h3_frame f;
  /* Truncate the buffer we hand to h3_frame_get so the frame's declared
   * Length (4) claims more than remains after the head. */
  CHECK(h3_frame_get(wired_span_of(buf, w - 2), &f) == 0);
}

/* Pinning: same bounds check under a different framing (mismatch between
 * declared Length and remaining buffer at any offset). */
static void test_h3_frame_length_mismatch_rejected(void) {
  u8         buf[16];
  wired_obuf ob      = {buf, sizeof buf, 0};
  u8         body[8] = {0};
  usz w = h3_frame_put(&ob, H3_FRAME_DATA, wired_span_of(body, sizeof body));

  h3_frame f;
  for (usz short_by = 1; short_by <= sizeof(body); short_by++) {
    CHECK(h3_frame_get(wired_span_of(buf, w - short_by), &f) == 0);
  }
}

/* RFC 9114 7.2.4: malformed SETTINGS are rejected -- wrong type, an
 * Identifier or Value cut off inside the payload, and more pairs than the
 * fixed H3_SETTINGS_MAX array (also refused on the put side). */
static void test_h3frame_settings_malformed(void) {
  static const u8 id_cut[]  = {H3_FRAME_SETTINGS, 0x01, 0x40};
  static const u8 val_cut[] = {H3_FRAME_SETTINGS, 0x01, 0x06};
  static const u8 data[]    = {H3_FRAME_DATA, 0x00};
  h3_settings     many      = {.n = H3_SETTINGS_MAX + 1};
  h3_settings     out;
  u8              buf[2 + 2 * (H3_SETTINGS_MAX + 1)];
  CHECK(h3_settings_get(data, 0, &out) == 0);
  CHECK(h3_settings_get(data, sizeof data, &out) == 0);
  CHECK(h3_settings_get(id_cut, sizeof id_cut, &out) == 0);
  CHECK(h3_settings_get(val_cut, sizeof val_cut, &out) == 0);
  {
    u8 roomy[256]; /* ample for 13 pairs: only the count bound refuses */
    CHECK(h3_settings_put(roomy, sizeof roomy, &many) == 0);
  }
  buf[0] = H3_FRAME_SETTINGS;
  buf[1] = 2 * (H3_SETTINGS_MAX + 1);
  for (usz i = 2; i < sizeof buf; i++) {
    buf[i] = 0x21; /* reserved id/value, one byte each */
  }
  CHECK(h3_settings_get(buf, sizeof buf - 2, &out) == 0); /* Length overrun */
  CHECK(h3_settings_get(buf, sizeof buf, &out) == 0);
  buf[1] = 2 * H3_SETTINGS_MAX;
  CHECK(h3_settings_get(buf, sizeof buf - 2, &out) == sizeof buf - 2);
  CHECK(out.n == H3_SETTINGS_MAX);
}

void test_h3frame(void) {
  test_h3frame_settings_malformed();
  test_h3frame_generic();
  test_h3frame_push_ids();
  test_h3frame_settings();
  test_h3frame_get_length_exceeds_buffer_rejected();
  test_h3_frame_length_mismatch_rejected();
}
