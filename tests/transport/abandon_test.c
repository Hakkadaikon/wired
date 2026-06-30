#include "test.h"

/* The connection is abandoned only when no offered version (ignoring reserved
 * GREASE values) is one we support. */
void test_abandon(void)
{
    u32 support[2] = {QUIC_VERSION_1, QUIC_VERSION_2};

    /* a supported version is offered -> do not abandon */
    u32 ok[1] = {QUIC_VERSION_2};
    CHECK(quic_version_must_abandon(ok, 1, support, 2) == 0);

    /* only unsupported versions offered -> abandon */
    u32 bad[2] = {0x11112222u, 0x33334444u};
    CHECK(quic_version_must_abandon(bad, 2, support, 2) == 1);

    /* empty offer -> abandon */
    CHECK(quic_version_must_abandon(bad, 0, support, 2) == 1);

    /* reserved GREASE value matching our support must be ignored: a reserved
     * 0x?a?a?a?a value is never a usable offer */
    u32 grease[1] = {0x0a0a0a0au};
    CHECK(quic_version_is_reserved(0x0a0a0a0au) == 1);
    CHECK(quic_version_must_abandon(grease, 1, support, 2) == 1);

    /* GREASE alongside a supported version -> not abandoned */
    u32 mixed[2] = {0x0a0a0a0au, QUIC_VERSION_1};
    CHECK(quic_version_must_abandon(mixed, 2, support, 2) == 0);
}
