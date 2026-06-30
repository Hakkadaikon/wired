#include "test.h"

/* RFC 9000 7.2: the client seeds a random first DCID and its own SCID; the
 * send DCID starts equal to that first DCID. */
static void test_cidxchg_init(void)
{
    quic_cidxchg x;
    u8 dcid[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    u8 scid[4] = { 1, 2, 3, 4 };
    CHECK(quic_cidxchg_init(&x, dcid, 8, scid, 4) == 1);
    CHECK(x.dcid_len == 8 && x.dcid[0] == 9 && x.dcid[7] == 2);
    CHECK(x.own_scid_len == 4 && x.own_scid[3] == 4);
    CHECK(x.init_dcid_len == 8 && x.init_dcid[0] == 9);
}

/* RFC 9000 7.2: once the server's SCID is seen, it becomes the send DCID; the
 * recorded first DCID (the ODCID) is left untouched. */
static void test_cidxchg_switch_dcid(void)
{
    quic_cidxchg x;
    u8 dcid[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    u8 scid[4] = { 1, 2, 3, 4 };
    u8 srv[5] = { 11, 12, 13, 14, 15 };
    quic_cidxchg_init(&x, dcid, 8, scid, 4);
    CHECK(quic_cidxchg_on_server_scid(&x, srv, 5) == 1);
    CHECK(x.dcid_len == 5 && x.dcid[0] == 11 && x.dcid[4] == 15);
    CHECK(x.init_dcid_len == 8 && x.init_dcid[0] == 9); /* ODCID unchanged */
}

/* RFC 9000 7.3: the server records the first Initial's DCID, then a matching
 * ODCID transport parameter verifies and a differing one is rejected. */
static void test_cidxchg_odcid_roundtrip(void)
{
    quic_cidxchg x;
    u8 first[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    u8 bad[8] = { 1, 2, 3, 4, 5, 6, 7, 9 };
    CHECK(quic_cidxchg_init(&x, (const u8 *)0, 0, (const u8 *)0, 0) == 1);
    CHECK(quic_cidxchg_remember_odcid(&x, first, 8) == 1);
    CHECK(quic_cidxchg_verify_odcid(&x, first, 8) == 1);
    CHECK(quic_cidxchg_verify_odcid(&x, bad, 8) == 0);       /* byte differs */
    CHECK(quic_cidxchg_verify_odcid(&x, first, 7) == 0);     /* length differs */
}

/* The client path: verify ODCID against the DCID seeded at init. */
static void test_cidxchg_client_verify(void)
{
    quic_cidxchg x;
    u8 dcid[6] = { 21, 22, 23, 24, 25, 26 };
    quic_cidxchg_init(&x, dcid, 6, dcid, 6);
    quic_cidxchg_on_server_scid(&x, dcid, 6); /* switch must not lose ODCID */
    CHECK(quic_cidxchg_verify_odcid(&x, dcid, 6) == 1);
}

/* Boundary: 0-length and the maximum 20-byte CID are accepted; 21 rejected. */
static void test_cidxchg_len_bounds(void)
{
    quic_cidxchg x;
    u8 big[21] = { 0 };
    CHECK(quic_cidxchg_init(&x, big, 20, big, 20) == 1 && x.dcid_len == 20);
    CHECK(quic_cidxchg_init(&x, big, 21, big, 0) == 0);     /* dcid too long */
    CHECK(quic_cidxchg_init(&x, big, 0, big, 21) == 0);     /* scid too long */
    CHECK(quic_cidxchg_on_server_scid(&x, big, 21) == 0);
    CHECK(quic_cidxchg_remember_odcid(&x, big, 21) == 0);
}

/* RFC 9000 7.3: ISCID/RSCID are verified with the tpverify primitives the
 * exchange composes — peer SCID matches, Retry SCID consistency holds. */
static void test_cidxchg_iscid_rscid(void)
{
    u8 peer_scid[4] = { 7, 7, 7, 7 };
    u8 retry_scid[3] = { 5, 6, 7 };
    CHECK(quic_tpverify_iscid(peer_scid, 4, peer_scid, 4) == 1);
    CHECK(quic_tpverify_iscid(peer_scid, 4, retry_scid, 3) == 0);
    /* Retry occurred: RSCID present and equal -> consistent. */
    CHECK(quic_tpverify_rscid(1, retry_scid, 3, retry_scid, 3, 1) == 1);
    /* No Retry but RSCID present -> violation. */
    CHECK(quic_tpverify_rscid(0, retry_scid, 3, retry_scid, 3, 1) == 0);
}

void test_cidxchg(void)
{
    test_cidxchg_init();
    test_cidxchg_switch_dcid();
    test_cidxchg_odcid_roundtrip();
    test_cidxchg_client_verify();
    test_cidxchg_len_bounds();
    test_cidxchg_iscid_rscid();
}
