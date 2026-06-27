#include "test.h"
#include "tparam/tpcheck.c"

/* RFC 9000 7.3 / 18.2: connection-ID transport parameters are authenticated
 * against the connection IDs observed on the wire. */
void test_tpcheck(void)
{
    static const u8 a[] = {0x01, 0x02, 0x03, 0x04};
    static const u8 b[] = {0x01, 0x02, 0x03, 0x04};
    static const u8 c[] = {0x01, 0x02, 0x03, 0x05}; /* differs in last byte */
    static const u8 z[] = {0};

    /* byte-for-byte match, including length */
    CHECK(quic_tparam_cid_match(a, 4, b, 4) == 1);
    CHECK(quic_tparam_cid_match(a, 4, c, 4) == 0);
    CHECK(quic_tparam_cid_match(a, 4, a, 3) == 0); /* length mismatch */
    CHECK(quic_tparam_cid_match(z, 0, z, 0) == 1); /* both empty (zero-length CID) */

    /* initial_source_connection_id vs the peer's observed Source CID */
    CHECK(quic_tparam_check_initial_scid(a, 4, b, 4) == 1);
    CHECK(quic_tparam_check_initial_scid(a, 4, c, 4) == 0);

    /* original_destination_connection_id vs the DCID the client sent */
    CHECK(quic_tparam_check_original_dcid(a, 4, b, 4) == 1);
    CHECK(quic_tparam_check_original_dcid(a, 4, c, 4) == 0);

    /* retry_source_connection_id: present iff a Retry was processed */
    CHECK(quic_tparam_check_retry_scid(1, 1, a, 4, b, 4) == 1); /* retry, matches */
    CHECK(quic_tparam_check_retry_scid(1, 1, a, 4, c, 4) == 0); /* retry, mismatch */
    CHECK(quic_tparam_check_retry_scid(1, 0, 0, 0, b, 4) == 0); /* retry but missing */
    CHECK(quic_tparam_check_retry_scid(0, 1, a, 4, 0, 0) == 0); /* present but no retry */
    CHECK(quic_tparam_check_retry_scid(0, 0, 0, 0, 0, 0) == 1); /* no retry, absent */
}
