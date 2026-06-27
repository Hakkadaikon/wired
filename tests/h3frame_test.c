#include "test.h"

static int h3f_bytes_eq(const u8 *a, const u8 *b, usz n)
{
    for (usz i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

/* Generic DATA/HEADERS frames round-trip type + length + opaque payload. */
static void test_h3frame_generic(void)
{
    u8 body[] = {0xde, 0xad, 0xbe, 0xef};
    u8 buf[16];
    usz w = quic_h3_frame_put(buf, sizeof(buf), QUIC_H3_FRAME_DATA, body, sizeof(body));
    CHECK(w == 2 + sizeof(body) && buf[0] == QUIC_H3_FRAME_DATA);

    u64 type, len;
    const u8 *pl;
    usz r = quic_h3_frame_get(buf, w, &type, &pl, &len);
    CHECK(r == w && type == QUIC_H3_FRAME_DATA && len == sizeof(body));
    CHECK(h3f_bytes_eq(pl, body, sizeof(body)));

    /* HEADERS carries an opaque (QPACK) block the same way. */
    u8 hb[] = {0x01, 0x02, 0x03};
    usz hw = quic_h3_frame_put(buf, sizeof(buf), QUIC_H3_FRAME_HEADERS, hb, sizeof(hb));
    usz hr = quic_h3_frame_get(buf, hw, &type, &pl, &len);
    CHECK(hr == hw && type == QUIC_H3_FRAME_HEADERS && h3f_bytes_eq(pl, hb, sizeof(hb)));

    /* truncated: Length claims 4 bytes but only 3 are present */
    CHECK(quic_h3_frame_get(buf, hw - 1, &type, &pl, &len) == 0);
}

/* CANCEL_PUSH / MAX_PUSH_ID carry a Push ID; GOAWAY a Stream/Push ID. */
static void test_h3frame_push_ids(void)
{
    u8 buf[16];
    u64 v;
    usz w = quic_h3_cancel_push_put(buf, sizeof(buf), 0x1234);
    CHECK(w != 0 && buf[0] == QUIC_H3_FRAME_CANCEL_PUSH);
    CHECK(quic_h3_cancel_push_get(buf, w, &v) == w && v == 0x1234);
    CHECK(quic_h3_cancel_push_get(buf, w - 1, &v) == 0);

    usz gw = quic_h3_goaway_put(buf, sizeof(buf), 40);
    CHECK(gw != 0 && buf[0] == QUIC_H3_FRAME_GOAWAY);
    CHECK(quic_h3_goaway_get(buf, gw, &v) == gw && v == 40);
    CHECK(quic_h3_goaway_get(buf, gw - 1, &v) == 0);

    usz mw = quic_h3_max_push_id_put(buf, sizeof(buf), 7);
    CHECK(mw != 0 && buf[0] == QUIC_H3_FRAME_MAX_PUSH_ID);
    CHECK(quic_h3_max_push_id_get(buf, mw, &v) == mw && v == 7);
    CHECK(quic_h3_max_push_id_get(buf, mw - 1, &v) == 0);

    /* type mismatch is rejected (GOAWAY bytes decoded as CANCEL_PUSH) */
    CHECK(quic_h3_cancel_push_get(buf, mw, &v) == 0);
}

/* SETTINGS round-trips multiple (id, value) pairs including the field size. */
static void test_h3frame_settings(void)
{
    quic_h3_settings in = {.n = 2};
    in.pairs[0].id = QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE;
    in.pairs[0].value = 0x4000;
    in.pairs[1].id = 0x21;
    in.pairs[1].value = 99;
    u8 buf[32];
    usz w = quic_h3_settings_put(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_H3_FRAME_SETTINGS);

    quic_h3_settings out;
    usz r = quic_h3_settings_get(buf, w, &out);
    CHECK(r == w && out.n == 2);
    CHECK(out.pairs[0].id == QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
    CHECK(out.pairs[0].value == 0x4000);
    CHECK(out.pairs[1].id == 0x21 && out.pairs[1].value == 99);

    /* truncated: a pair's value varint is cut off */
    CHECK(quic_h3_settings_get(buf, w - 1, &out) == 0);

    /* empty SETTINGS is valid and round-trips to zero pairs */
    quic_h3_settings empty = {.n = 0};
    usz ew = quic_h3_settings_put(buf, sizeof(buf), &empty);
    CHECK(quic_h3_settings_get(buf, ew, &out) == ew && out.n == 0);
}

void test_h3frame(void)
{
    test_h3frame_generic();
    test_h3frame_push_ids();
    test_h3frame_settings();
}
