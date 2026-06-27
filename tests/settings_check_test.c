#include "test.h"
#include "h3/settings_check.c"
#include "h3/frame.h"

/* The HTTP/2-reserved identifiers 0x02..0x05 are forbidden in HTTP/3. */
static void test_settings_reserved(void)
{
    CHECK(quic_h3_setting_allowed(0x02) == 0);
    CHECK(quic_h3_setting_allowed(0x03) == 0);
    CHECK(quic_h3_setting_allowed(0x04) == 0);
    CHECK(quic_h3_setting_allowed(0x05) == 0);
}

/* Known and boundary identifiers are allowed. */
static void test_settings_allowed(void)
{
    CHECK(quic_h3_setting_allowed(0x00) == 1);                          /* below */
    CHECK(quic_h3_setting_allowed(0x01) == 1);                          /* just below */
    CHECK(quic_h3_setting_allowed(0x06) == 1);                          /* MAX_FIELD_SECTION_SIZE */
    CHECK(quic_h3_setting_allowed(QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE) == 1);
    CHECK(quic_h3_setting_allowed(0x07) == 1);                          /* just above */
}

/* Unknown / large identifiers are allowed (ignored, not an error). */
static void test_settings_unknown(void)
{
    CHECK(quic_h3_setting_allowed(0x21) == 1);                          /* a GREASE-ish id */
    CHECK(quic_h3_setting_allowed(0xffffffffffffffffUL) == 1);
}

void test_settings_check(void)
{
    test_settings_reserved();
    test_settings_allowed();
    test_settings_unknown();
}
