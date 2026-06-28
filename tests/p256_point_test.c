#include "test.h"
#include "p256/p256_point.h"

/* G lies on the curve. */
static void test_p256_g_on_curve(void)
{
    CHECK(quic_ec_on_curve(&quic_p256_g));
}

/* 2G via double equals G + G via add, and is on the curve. */
static void test_p256_double_eq_add(void)
{
    ec_point d, s;
    quic_ec_double(&d, &quic_p256_g);
    quic_ec_add(&s, &quic_p256_g, &quic_p256_g);
    CHECK(!d.inf && !s.inf);
    CHECK(quic_fp_eq(d.x, s.x));
    CHECK(quic_fp_eq(d.y, s.y));
    CHECK(quic_ec_on_curve(&d));
}

/* (n)*G is the point at infinity; also 1*G == G. */
static void test_p256_scalar(void)
{
    ec_point one_g, kg;
    u8 k1[32] = {0}; k1[31] = 1;
    u8 nbytes[32];
    quic_fp_to_be(nbytes, quic_p256_n);
    quic_ec_mul(&one_g, k1, &quic_p256_g);
    CHECK(!one_g.inf && quic_fp_eq(one_g.x, quic_p256_g.x));
    quic_ec_mul(&kg, nbytes, &quic_p256_g);
    CHECK(kg.inf);
}

void test_p256_point(void)
{
    test_p256_g_on_curve();
    test_p256_double_eq_add();
    test_p256_scalar();
}
