#include "test.h"
#include "transport/version/versmgr/v2switch.h"
#include "transport/version/version/version.h"

void test_v2switch(void)
{
    CHECK(quic_vers_is_v2(QUIC_VERSION_2) == 1);
    CHECK(quic_vers_is_v2(QUIC_VERSION_1) == 0);

    /* initial salt differs between v1 and v2 */
    const u8 *s1 = 0, *s2 = 0;
    usz l1 = 0, l2 = 0;
    CHECK(quic_vers_initial_salt(QUIC_VERSION_1, &s1, &l1) == 1);
    CHECK(quic_vers_initial_salt(QUIC_VERSION_2, &s2, &l2) == 1);
    CHECK(l1 == 20 && l2 == 20);
    int same = 1;
    for (usz i = 0; i < 20; i++)
        if (s1[i] != s2[i]) same = 0;
    CHECK(same == 0);
    CHECK(quic_vers_initial_salt(0x5u, &s1, &l1) == 0);

    /* label prefixes */
    const char *p = 0;
    usz pl = 0;
    CHECK(quic_vers_label_prefix(QUIC_VERSION_1, &p, &pl) == 1);
    CHECK(pl == 5 && p[0] == 'q' && p[4] == ' ');
    CHECK(quic_vers_label_prefix(QUIC_VERSION_2, &p, &pl) == 1);
    CHECK(pl == 7 && p[4] == 'v' && p[5] == '2');
    CHECK(quic_vers_label_prefix(0x5u, &p, &pl) == 0);
}
