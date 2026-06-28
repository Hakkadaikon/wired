#include "test.h"

/* RFC 9114 4.3.1: a GET request field section is the empty prefix followed by
 * :method GET (static 17), :scheme https (23), :authority (literal), :path (1
 * when "/"). */
static void test_get_field_section(void)
{
    u8 out[64];
    usz n = 0;
    const u8 *path = (const u8 *)"/", *authority = (const u8 *)"example.com";
    u64 idx = 0;
    int is_static = 0, never = 0;
    usz used, vlen = 0;
    u8 val[32];
    CHECK(quic_h3req_enc_get(path, 1, authority, 11, out, sizeof out, &n) == 1);
    CHECK(out[0] == 0x00 && out[1] == 0x00);
    /* :method GET indexed. */
    used = quic_qpack_indexed_decode(out + 2, n - 2, &idx, &is_static);
    CHECK(used == 1 && idx == 17);
    /* :scheme https indexed. */
    used = quic_qpack_indexed_decode(out + 3, n - 3, &idx, &is_static);
    CHECK(used == 1 && idx == 23);
    /* :authority literal name reference (idx 0), value echoed. */
    used = quic_qpack_literal_namref_decode(out + 4, n - 4, &idx, &is_static,
                                            &never, val, sizeof val, &vlen);
    CHECK(used != 0 && idx == 0 && vlen == 11 && val[0] == 'e');
    /* :path / indexed (idx 1). */
    used = quic_qpack_indexed_decode(out + 4 + used, n - 4 - used, &idx,
                                     &is_static);
    CHECK(used == 1 && idx == 1);
}

/* Insufficient capacity fails. */
static void test_get_overflow(void)
{
    u8 out[3];
    usz n = 0;
    const u8 *path = (const u8 *)"/", *authority = (const u8 *)"example.com";
    CHECK(quic_h3req_enc_get(path, 1, authority, 11, out, sizeof out, &n) == 0);
}

void test_request_headers(void)
{
    test_get_field_section();
    test_get_overflow();
}
