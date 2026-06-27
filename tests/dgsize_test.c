#include "test.h"

/* RFC 9221 5: payload upper bound is max_frame_size minus the type byte and,
 * for type 0x31, the length varint that encodes the payload size. */
void test_dgsize(void)
{
    /* too small to hold type + any payload */
    CHECK(quic_datagram_max_payload(0, 1) == 0);
    CHECK(quic_datagram_max_payload(1, 1) == 0);

    /* 0x30: only the type byte is overhead */
    CHECK(quic_datagram_max_payload(1201, 0) == 1200);

    /* 0x31: type + length varint. room = 64 -> payload 63 (varint width 1) */
    CHECK(quic_datagram_max_payload(65, 1) == 63);
    /* boundary where a 1-byte varint can no longer grow: room 65 -> 63 */
    CHECK(quic_datagram_max_payload(66, 1) == 63);
    /* room 67 -> 64 (varint widens to 2 bytes) */
    CHECK(quic_datagram_max_payload(67, 1) == 64);

    /* typical: 1200-byte frame limit, explicit length */
    CHECK(quic_datagram_max_payload(1200, 1) == 1197); /* 1199 - 2 */
}
