#include "test.h"

/* A client Initial (long, non-zero version, Initial type) is a flow start. */
static void test_flowobs_start(void)
{
    CHECK(quic_manage_is_flow_start(0xC0, 1) == 1); /* Initial, v1 */
    CHECK(quic_manage_is_flow_start(0xE0, 1) == 0); /* Handshake, not start */
    CHECK(quic_manage_is_flow_start(0x40, 1) == 0); /* short header */
}

/* A Version Negotiation packet (long, version 0) is detected and is not a
 * flow start. */
static void test_flowobs_vneg(void)
{
    CHECK(quic_manage_is_vneg(0xC0, 0) == 1);     /* long, version 0 */
    CHECK(quic_manage_is_vneg(0x40, 0) == 0);     /* short header */
    CHECK(quic_manage_is_vneg(0xC0, 1) == 0);     /* non-zero version */
    CHECK(quic_manage_is_flow_start(0xC0, 0) == 0); /* vneg is not a start */
}

void test_flowobs(void)
{
    test_flowobs_start();
    test_flowobs_vneg();
}
