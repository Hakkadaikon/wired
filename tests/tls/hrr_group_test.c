#include "test.h"
#include "tls/handshake/core/hrr/hrr_group.h"
#include "tls/handshake/core/hrr/hrr_build.h"
#include "tls/handshake/roles/shbuild/shbuild.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.1.4: the client recovers the selected_group from the HRR. */
static void test_hrr_group_extract(void)
{
    u8 out[256];
    usz len = 0;
    u16 group = 0;
    CHECK(quic_hrr_build(QUIC_GROUP_X25519, 0, 0, out, sizeof out, &len) == 1);
    CHECK(quic_hrr_selected_group(out, len, &group) == 1);
    CHECK(group == QUIC_GROUP_X25519);
}

/* A cookie before/after key_share does not disturb extraction. */
static void test_hrr_group_with_cookie(void)
{
    u8 out[256], ck[3] = {9, 8, 7};
    usz len = 0;
    u16 group = 0;
    CHECK(quic_hrr_build(QUIC_GROUP_X25519, ck, 3, out, sizeof out, &len) == 1);
    CHECK(quic_hrr_selected_group(out, len, &group) == 1);
    CHECK(group == QUIC_GROUP_X25519);
}

/* A ServerHello with a full key_share (group + key) is not the HRR form, but
 * its selected_group is still the group field; absence of key_share yields 0. */
static void test_hrr_group_absent(void)
{
    u8 buf[10] = {0x02};
    u16 group = 123;
    CHECK(quic_hrr_selected_group(buf, 10, &group) == 0);
    CHECK(quic_hrr_selected_group(buf, 0, &group) == 0);
}

void test_hrr_group(void)
{
    test_hrr_group_extract();
    test_hrr_group_with_cookie();
    test_hrr_group_absent();
}
