#include "test.h"
#include "version/version.h"
#include "tls/handshake/core/handshake_drive/vn_drive.h"

/* Encode versions as the VN packet's 4-big-endian-bytes-each list. */
static void enc(u8 *buf, const u32 *v, usz n)
{
    for (usz i = 0; i < n; i++) {
        buf[i*4+0] = (u8)(v[i] >> 24); buf[i*4+1] = (u8)(v[i] >> 16);
        buf[i*4+2] = (u8)(v[i] >> 8);  buf[i*4+3] = (u8)v[i];
    }
}

/* Choose the highest-preference mutual version (our order wins). */
static void test_vn_choose_pref(void)
{
    u32 offered[2] = {QUIC_VERSION_1, QUIC_VERSION_2};
    u8 vn[8]; enc(vn, offered, 2);
    u32 mine[2] = {QUIC_VERSION_2, QUIC_VERSION_1}; /* prefer v2 */
    u32 chosen = 0;
    CHECK(quic_vn_choose(vn, 2, mine, 2, &chosen) == 1);
    CHECK(chosen == QUIC_VERSION_2);

    u32 mine1[2] = {QUIC_VERSION_1, QUIC_VERSION_2}; /* prefer v1 */
    chosen = 0;
    CHECK(quic_vn_choose(vn, 2, mine1, 2, &chosen) == 1);
    CHECK(chosen == QUIC_VERSION_1);
}

/* No mutual version: returns 0. */
static void test_vn_choose_none(void)
{
    u32 offered[1] = {0x0a0a0a0a}; /* reserved/GREASE, not ours */
    u8 vn[4]; enc(vn, offered, 1);
    u32 mine[1] = {QUIC_VERSION_1};
    u32 chosen = 0xdead;
    CHECK(quic_vn_choose(vn, 1, mine, 1, &chosen) == 0);
}

/* VN is ignored once the handshake has started (downgrade protection). */
static void test_vn_acceptable(void)
{
    CHECK(quic_vn_acceptable(0) == 1);
    CHECK(quic_vn_acceptable(1) == 0);
}

void test_vn_drive(void)
{
    test_vn_choose_pref();
    test_vn_choose_none();
    test_vn_acceptable();
}
