#include "test.h"
#include "asn1/derseq.h"
#include "asn1/der.h"

/* X.690 8.9. Walk a SEQUENCE of two INTEGERs. */
static void test_derseq_two_ints(void)
{
    /* SEQUENCE { INTEGER 1, INTEGER 256 } value bytes */
    const u8 seq[] = {0x02, 0x01, 0x01, 0x02, 0x02, 0x01, 0x00};
    quic_derseq c;
    quic_derseq_init(&c, seq, sizeof(seq));
    u8 tag;
    const u8 *val;
    usz vlen;
    CHECK(quic_derseq_next(&c, &tag, &val, &vlen) == 1);
    CHECK(tag == QUIC_DER_INTEGER && vlen == 1 && val[0] == 0x01);
    CHECK(quic_derseq_next(&c, &tag, &val, &vlen) == 1);
    CHECK(tag == QUIC_DER_INTEGER && vlen == 2 && val[0] == 0x01 && val[1] == 0x00);
    CHECK(quic_derseq_next(&c, &tag, &val, &vlen) == 0); /* end */
}

/* Nested SEQUENCE: outer holds an inner SEQUENCE then an INTEGER. */
static void test_derseq_nested(void)
{
    /* inner SEQUENCE {INTEGER 7} = 30 03 02 01 07 ; then INTEGER 9 */
    const u8 seq[] = {0x30, 0x03, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09};
    quic_derseq c;
    quic_derseq_init(&c, seq, sizeof(seq));
    u8 tag;
    const u8 *val;
    usz vlen;
    CHECK(quic_derseq_next(&c, &tag, &val, &vlen) == 1);
    CHECK(tag == QUIC_DER_SEQUENCE && vlen == 3);
    /* descend into the inner sequence's value */
    quic_derseq inner;
    quic_derseq_init(&inner, val, vlen);
    u8 itag;
    const u8 *ival;
    usz ilen;
    CHECK(quic_derseq_next(&inner, &itag, &ival, &ilen) == 1);
    CHECK(itag == QUIC_DER_INTEGER && ilen == 1 && ival[0] == 0x07);
    CHECK(quic_derseq_next(&inner, &itag, &ival, &ilen) == 0);
    /* back to outer */
    CHECK(quic_derseq_next(&c, &tag, &val, &vlen) == 1);
    CHECK(tag == QUIC_DER_INTEGER && vlen == 1 && val[0] == 0x09);
    CHECK(quic_derseq_next(&c, &tag, &val, &vlen) == 0);
}

static void test_derseq_truncated_element(void)
{
    /* element claims 4 octets but only 1 remains */
    const u8 seq[] = {0x02, 0x04, 0xAA};
    quic_derseq c;
    quic_derseq_init(&c, seq, sizeof(seq));
    u8 tag;
    const u8 *val;
    usz vlen;
    CHECK(quic_derseq_next(&c, &tag, &val, &vlen) == 0);
}

void test_derseq(void)
{
    test_derseq_two_ints();
    test_derseq_nested();
    test_derseq_truncated_element();
}
