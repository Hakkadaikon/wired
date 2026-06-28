#include "test.h"

/* RFC 9204 4.5 / RFC 9114 4.3.1: :method GET, :scheme https and :path / are all
 * in the QPACK static table, so they encode as Indexed Field Lines; :authority
 * with a real value is not, so it is a Literal With Name Reference. */
static void test_pseudo_indexed_and_namref(void)
{
    u8 out[64];
    usz n = 0;
    const u8 *m = (const u8 *)"GET", *s = (const u8 *)"https";
    const u8 *p = (const u8 *)"/", *a = (const u8 *)"example.com";
    CHECK(quic_h3req_enc_pseudo(m, 3, p, 1, s, 5, a, 11, out, sizeof out, &n)
          == 1);
    /* empty prefix (RIC 0, Base 0). */
    CHECK(out[0] == 0x00 && out[1] == 0x00);
    /* :method GET = static 17 -> 0x80|0x40|17, :scheme https = 23, :path / = 1. */
    CHECK(out[2] == 0xd1);
    CHECK(out[3] == 0xd7);
    /* :authority "example.com" is a literal name reference (01NTiiii). */
    CHECK((out[4] & 0xf0) == 0x50);
}

/* Round-trip: decode the Indexed and Literal field lines back and confirm the
 * pseudo-headers resolve to their static names/values. */
static void test_pseudo_roundtrip(void)
{
    u8 out[64];
    usz n = 0;
    const u8 *m = (const u8 *)"GET", *s = (const u8 *)"https";
    const u8 *p = (const u8 *)"/", *a = (const u8 *)"example.com";
    u64 idx = 0;
    int is_static = 0, never = 0;
    usz used, vlen = 0;
    u8 val[32];
    const char *nm, *vv;
    CHECK(quic_h3req_enc_pseudo(m, 3, p, 1, s, 5, a, 11, out, sizeof out, &n)
          == 1);
    /* first field line after the 2-byte prefix: Indexed :method GET (idx 17). */
    used = quic_qpack_indexed_decode(out + 2, n - 2, &idx, &is_static);
    CHECK(used == 1 && is_static == 1 && idx == 17);
    CHECK(quic_qpack_static_get((usz)idx, &nm, &vv) == 1);
    CHECK(nm[0] == ':' && vv[0] == 'G');
    /* :authority literal: name index 0 resolves to ":authority", value echoed.
     * It follows prefix(2) + :method(1) + :scheme(1) at offset 4. */
    used = quic_qpack_literal_namref_decode(out + 4, n - 4, &idx, &is_static,
                                            &never, val, sizeof val, &vlen);
    CHECK(used != 0 && is_static == 1 && idx == 0);
    CHECK(vlen == 11 && val[0] == 'e' && val[10] == 'm');
    CHECK(quic_qpack_static_get((usz)idx, &nm, &vv) == 1);
    CHECK(nm[1] == 'a'); /* ":authority" */
}

/* Insufficient capacity fails without overrun. */
static void test_pseudo_overflow(void)
{
    u8 out[3];
    usz n = 0;
    const u8 *m = (const u8 *)"GET", *s = (const u8 *)"https";
    const u8 *p = (const u8 *)"/", *a = (const u8 *)"example.com";
    CHECK(quic_h3req_enc_pseudo(m, 3, p, 1, s, 5, a, 11, out, sizeof out, &n)
          == 0);
}

void test_pseudo_encode(void)
{
    test_pseudo_indexed_and_namref();
    test_pseudo_roundtrip();
    test_pseudo_overflow();
}
