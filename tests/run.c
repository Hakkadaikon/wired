#include "test.h"
#include "varint_test.c"
#include "header_test.c"
#include "pnum_test.c"
#include "tparam_test.c"
#include "frame_test.c"
#include "fsm/fsm.c"
#include "stream_test.c"
#include "conn_test.c"
#include "sha256_test.c"
#include "hmac_test.c"
#include "hkdf_test.c"
#include "aes_test.c"
#include "gcm_test.c"
#include "chacha20_test.c"
#include "poly1305_test.c"
#include "aead_test.c"
#include "initial_test.c"
#include "hp_test.c"
#include "rtt_test.c"
#include "sent_test.c"
#include "cc_test.c"
#include "flow_test.c"
#include "udp_test.c"
#include "retransmit_test.c"
#include "ack_test.c"
#include "ncid_test.c"
#include "protect_test.c"
#include "net_test.c"
#include "x25519_test.c"
#include "handshake_test.c"
#include "schedule_test.c"
#include "endpoint_test.c"
#include "stream_ctl_test.c"
#include "connctl_test.c"
#include "dispatch_test.c"
#include "flowctl_test.c"

int main(void)
{
    test_varint();
    test_header();
    test_pnum();
    test_tparam();
    test_frame();
    test_stream();
    test_conn();
    test_sha256();
    test_hmac();
    test_hkdf();
    test_aes();
    test_gcm();
    test_chacha20();
    test_poly1305();
    test_aead();
    test_initial();
    test_hp();
    test_rtt();
    test_sent();
    test_cc();
    test_flow();
    test_udp();
    test_rtx();
    test_ack();
    test_ncid();
    test_protect();
    test_net();
    test_x25519();
    test_handshake();
    test_schedule();
    test_endpoint();
    test_stream_ctl();
    test_connctl();
    test_dispatch();
    test_flowctl();
    return TEST_REPORT();
}
