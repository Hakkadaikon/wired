#include "test.h"
#include "versmgr/avail.h"
#include "version/version.h"

void test_avail(void)
{
    quic_vers_set s;
    quic_vers_init(&s);

    /* supports v1 and v2, not unknown */
    CHECK(quic_vers_supports(&s, QUIC_VERSION_1) == 1);
    CHECK(quic_vers_supports(&s, QUIC_VERSION_2) == 1);
    CHECK(quic_vers_supports(&s, 0x00000005u) == 0);

    /* common version: peer offers v1 only -> v1 */
    u32 peer_v1[] = {QUIC_VERSION_1};
    u32 chosen = 0;
    CHECK(quic_vers_choose_compatible(&s, peer_v1, 1, &chosen) == 1);
    CHECK(chosen == QUIC_VERSION_1);

    /* peer offers both -> our most preferred (v2) */
    u32 peer_both[] = {QUIC_VERSION_1, QUIC_VERSION_2};
    chosen = 0;
    CHECK(quic_vers_choose_compatible(&s, peer_both, 2, &chosen) == 1);
    CHECK(chosen == QUIC_VERSION_2);

    /* no common version */
    u32 peer_none[] = {0x00000005u};
    chosen = 0xdead;
    CHECK(quic_vers_choose_compatible(&s, peer_none, 1, &chosen) == 0);
    CHECK(chosen == 0xdead);
}
