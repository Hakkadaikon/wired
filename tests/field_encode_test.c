#include "test.h"

/* RFC 9204 4.5: :status 200 is in the static table, so the field section is
 * the 2-byte empty prefix followed by an Indexed Field Line (1Tiiiiii). */
static void test_field_encode_status_200(void)
{
    u8 out[16];
    usz n = 0;
    CHECK(quic_h3resp_encode_status(200, out, sizeof out, &n) == 1);
    /* prefix: Required Insert Count 0, Delta Base 0. */
    CHECK(n == 3);
    CHECK(out[0] == 0x00 && out[1] == 0x00);
    /* static index 25 (:status 200): 0x80|0x40|25 = 0xd9. */
    CHECK(out[2] == 0xd9);
}

/* A status absent from the static table is a Literal Field Line referencing
 * the :status name (static index 24) with the decimal value. */
static void test_field_encode_status_201(void)
{
    u8 out[16];
    usz n = 0;
    const u8 *p;
    usz pl = 0;
    u64 idx = 0;
    int is_static = 0, never = 0;
    u8 val[8];
    CHECK(quic_h3resp_encode_status(201, out, sizeof out, &n) == 1);
    CHECK(out[0] == 0x00 && out[1] == 0x00);
    p = out + 2;
    pl = quic_qpack_literal_namref_decode(p, n - 2, &idx, &is_static, &never,
                                          val, sizeof val, &n);
    CHECK(pl != 0);
    CHECK(is_static == 1 && idx == 24);
    CHECK(n == 3 && val[0] == '2' && val[1] == '0' && val[2] == '1');
}

/* A second in-table status confirms the Indexed index comes from the static
 * lookup, not a hard-coded 25: :status 404 is static index 27 -> 0x80|0x40|27. */
static void test_field_encode_status_404(void)
{
    u8 out[16];
    usz n = 0;
    CHECK(quic_h3resp_encode_status(404, out, sizeof out, &n) == 1);
    CHECK(n == 3 && out[0] == 0x00 && out[1] == 0x00);
    CHECK(out[2] == 0xdb);
}

/* Insufficient capacity fails without writing past the buffer. */
static void test_field_encode_overflow(void)
{
    u8 out[2];
    usz n = 0;
    CHECK(quic_h3resp_encode_status(200, out, sizeof out, &n) == 0);
}

void test_field_encode(void)
{
    test_field_encode_status_200();
    test_field_encode_status_201();
    test_field_encode_status_404();
    test_field_encode_overflow();
}
