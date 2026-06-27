#include "test.h"

/* RFC 9114 reserved (grease) values 0x1f*N + 0x21 are recognized so a
 * receiver can ignore them across frame/stream/setting/error spaces. */
static void test_h3grease(void)
{
    CHECK(quic_h3_is_reserved(0x21) == 1);        /* N=0 */
    CHECK(quic_h3_is_reserved(0x21 + 0x1f) == 1); /* N=1 = 0x40 */
    CHECK(quic_h3_is_reserved(0x21 + 0x1f * 7) == 1);
    CHECK(quic_h3_is_reserved(0x20) == 0);        /* below first point */
    CHECK(quic_h3_is_reserved(0x04) == 0);        /* SETTINGS, a real type */
    CHECK(quic_h3_is_reserved(0x00) == 0);        /* DATA, a real type */
}
