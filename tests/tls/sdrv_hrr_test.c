#include "common/diag/error/error.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "test.h"
#include "tls/handshake/core/hrr/hrr_build.h"
#include "tls/handshake/core/hrr/hrr_detect.h"
#include "tls/handshake/core/sdrv/sdrv.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"

/* RFC 8446 4.1.4 / 4.4.1: HelloRetryRequest sent when the ClientHello's
 * key_share does not offer this driver's only supported group (x25519), the
 * post-HRR ClientHello2 cipher_suite check, and the message_hash transcript
 * transform. */

/* Fixed offset of the key_share extension's group field within a ClientHello
 * built by sdrv_test_client_hello (sdrv_test.c's SDRV_TEST_KEYSHARE_TYPE_OFF
 * doc): type(2) ext_len(2) shares_len(2) group(2) at type_off+6. */
#define SDRV_HRR_KEYSHARE_TYPE_OFF 74
#define SDRV_HRR_KEYSHARE_GROUP_OFF (SDRV_HRR_KEYSHARE_TYPE_OFF + 6)

/* RFC 8446 4.1.2: the single cipher_suites entry's message offset (see
 * sdrv_test.c's SDRV_TEST_CIPHER_SUITE_OFF doc). */
#define SDRV_HRR_CIPHER_SUITE_OFF 41

static usz sdrv_hrr_build_ch(
    u8* ch, usz cap, const u8* cli_pub, const u8* srv_random) {
  return tls_client_hello(
      &(clienthello_in){
          srv_random, cli_pub, wired_span_of(0, 0), wired_span_of(0, 0)},
      &(wired_obuf){ch, cap, 0});
}

/* Overwrite the key_share group field so the ClientHello no longer offers
 * x25519 -- the only group this driver supports, so this is exactly the
 * condition sdrv_recv_client_hello must recognise as "need an HRR". */
static void sdrv_hrr_drop_x25519(u8* ch) {
  ch[SDRV_HRR_KEYSHARE_GROUP_OFF]     = (u8)(GROUP_SECP256R1 >> 8);
  ch[SDRV_HRR_KEYSHARE_GROUP_OFF + 1] = (u8)GROUP_SECP256R1;
}

static void sdrv_hrr_set_suite(u8* ch, u16 suite) {
  ch[SDRV_HRR_CIPHER_SUITE_OFF]     = (u8)(suite >> 8);
  ch[SDRV_HRR_CIPHER_SUITE_OFF + 1] = (u8)suite;
}

static void sdrv_hrr_init_any(sdrv* s) {
  u8 srv_priv[32], srv_pub[32], cert_priv[32];
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  wired_x25519_base(srv_pub, srv_priv);
  {
    sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
    sdrv_init(s, &din);
  }
}

/* A well-formed key/random fixture shared by the tests below: a client
 * key pair and server random, common to every scenario. */
typedef struct {
  u8 cli_pub[32];
  u8 srv_random[32];
} sdrv_hrr_fixture;

static void sdrv_hrr_fixture_init(sdrv_hrr_fixture* f) {
  u8 cli_priv[32];
  for (usz i = 0; i < 32; i++) {
    cli_priv[i]      = (u8)(i + 1);
    f->srv_random[i] = (u8)(0xa0 + i);
  }
  wired_x25519_base(f->cli_pub, cli_priv);
}

/* (a) A normal ClientHello (real x25519 key_share) is accepted exactly as
 * before, with no HRR pending -- the pre-existing non-HRR path must not
 * regress. */
static void test_sdrv_hrr_normal_ch_no_hrr_pending(void) {
  sdrv_hrr_fixture f;
  u8               ch[512];
  usz              ch_len;
  sdrv             s;
  sdrv_hrr_fixture_init(&f);
  ch_len = sdrv_hrr_build_ch(ch, sizeof(ch), f.cli_pub, f.srv_random);
  CHECK(ch_len != 0);
  sdrv_hrr_init_any(&s);
  CHECK(sdrv_recv_client_hello(&s, ch, ch_len) == 1);
  CHECK(sdrv_hrr_pending(&s) == 0);
}

/* (b) A ClientHello offering only secp256r1 (no x25519) arms HRR, and
 * sdrv_build_hrr emits a real HelloRetryRequest recognised by
 * hrr_is_hello_retry. */
static void test_sdrv_hrr_no_x25519_triggers_hrr(void) {
  sdrv_hrr_fixture f;
  u8               ch[512], hrr[256];
  usz              ch_len;
  sdrv             s;
  wired_obuf       hob = obuf_of(hrr, sizeof(hrr));
  sdrv_hrr_fixture_init(&f);
  ch_len = sdrv_hrr_build_ch(ch, sizeof(ch), f.cli_pub, f.srv_random);
  CHECK(ch_len != 0);
  sdrv_hrr_drop_x25519(ch);
  sdrv_hrr_init_any(&s);
  CHECK(sdrv_recv_client_hello(&s, ch, ch_len) == 1);
  CHECK(sdrv_hrr_pending(&s) == 1);
  CHECK(sdrv_build_hrr(&s, &hob) == 1);
  CHECK(hrr_is_hello_retry(hrr, hob.len) == 1);
}

/* (c) A post-HRR ClientHello2 offering the same cipher_suite as
 * ClientHello1 negotiated is accepted, clearing hrr_pending again. */
static void test_sdrv_hrr_second_ch_same_cipher_accepted(void) {
  sdrv_hrr_fixture f;
  u8               ch1[512], ch2[512], hrr[256];
  usz              ch1_len, ch2_len;
  sdrv             s;
  wired_obuf       hob = obuf_of(hrr, sizeof(hrr));
  sdrv_hrr_fixture_init(&f);
  ch1_len = sdrv_hrr_build_ch(ch1, sizeof(ch1), f.cli_pub, f.srv_random);
  CHECK(ch1_len != 0);
  sdrv_hrr_drop_x25519(ch1);
  sdrv_hrr_init_any(&s);
  CHECK(sdrv_recv_client_hello(&s, ch1, ch1_len) == 1);
  CHECK(sdrv_build_hrr(&s, &hob) == 1);

  ch2_len = sdrv_hrr_build_ch(ch2, sizeof(ch2), f.cli_pub, f.srv_random);
  CHECK(ch2_len != 0);
  CHECK(sdrv_recv_client_hello(&s, ch2, ch2_len) == 1);
  CHECK(sdrv_hrr_pending(&s) == 0);
}

/* (d) A post-HRR ClientHello2 offering a DIFFERENT cipher_suite than
 * ClientHello1 negotiated is rejected (RFC 8446 4.1.2). */
static void test_sdrv_hrr_second_ch_diff_cipher_rejected(void) {
  sdrv_hrr_fixture f;
  u8               ch1[512], ch2[512], hrr[256];
  usz              ch1_len, ch2_len;
  sdrv             s;
  wired_obuf       hob = obuf_of(hrr, sizeof(hrr));
  sdrv_hrr_fixture_init(&f);
  ch1_len = sdrv_hrr_build_ch(ch1, sizeof(ch1), f.cli_pub, f.srv_random);
  CHECK(ch1_len != 0);
  sdrv_hrr_drop_x25519(ch1);
  sdrv_hrr_init_any(&s);
  CHECK(sdrv_recv_client_hello(&s, ch1, ch1_len) == 1);
  CHECK(sdrv_build_hrr(&s, &hob) == 1);

  ch2_len = sdrv_hrr_build_ch(ch2, sizeof(ch2), f.cli_pub, f.srv_random);
  CHECK(ch2_len != 0);
  sdrv_hrr_set_suite(ch2, TLS_CHACHA20_POLY1305_SHA256);
  CHECK(sdrv_recv_client_hello(&s, ch2, ch2_len) == 0);
}

/* (e) RFC 8446 4.4.1: after sdrv_build_hrr, the transcript equals
 * Hash-chain(message_hash(Hash(ClientHello1)) || HRR), not raw
 * ClientHello1 || HRR -- proven by recomputing the expected transcript hash
 * independently and comparing to the driver's own. */
static void test_sdrv_hrr_transcript_uses_message_hash(void) {
  sdrv_hrr_fixture f;
  u8               ch1[512], hrr[256];
  usz              ch1_len;
  sdrv             s;
  wired_obuf       hob = obuf_of(hrr, sizeof(hrr));
  u8               ch1_hash[32], mh[36], expect[32], got[32];
  usz              mh_len;
  transcript       expect_tr;

  sdrv_hrr_fixture_init(&f);
  ch1_len = sdrv_hrr_build_ch(ch1, sizeof(ch1), f.cli_pub, f.srv_random);
  CHECK(ch1_len != 0);
  sdrv_hrr_drop_x25519(ch1);
  sdrv_hrr_init_any(&s);
  CHECK(sdrv_recv_client_hello(&s, ch1, ch1_len) == 1);
  CHECK(sdrv_build_hrr(&s, &hob) == 1);

  wired_sha256(ch1, ch1_len, ch1_hash);
  mh_len = hrr_message_hash(ch1_hash, 32, mh, sizeof(mh));
  CHECK(mh_len == 36);
  transcript_init(&expect_tr);
  transcript_add(&expect_tr, mh, mh_len);
  transcript_add(&expect_tr, hrr, hob.len);
  transcript_hash(&expect_tr, expect);
  transcript_hash(&s.tr, got);
  for (int i = 0; i < 32; i++) CHECK(expect[i] == got[i]);
}

/* (f) RFC 8446 4.1.4: a client MUST NOT be sent a second HelloRetryRequest
 * -- a post-HRR ClientHello2 that still carries no usable key_share is
 * rejected outright (illegal_parameter, alert 47), never re-armed for
 * another HRR. */
static void test_sdrv_hrr_second_ch_still_no_share_rejected(void) {
  sdrv_hrr_fixture f;
  u8               ch1[512], ch2[512], hrr[256];
  usz              ch1_len, ch2_len;
  sdrv             s;
  wired_obuf       hob = obuf_of(hrr, sizeof(hrr));
  sdrv_hrr_fixture_init(&f);
  ch1_len = sdrv_hrr_build_ch(ch1, sizeof(ch1), f.cli_pub, f.srv_random);
  CHECK(ch1_len != 0);
  sdrv_hrr_drop_x25519(ch1);
  sdrv_hrr_init_any(&s);
  CHECK(sdrv_recv_client_hello(&s, ch1, ch1_len) == 1);
  CHECK(sdrv_build_hrr(&s, &hob) == 1);

  ch2_len = sdrv_hrr_build_ch(ch2, sizeof(ch2), f.cli_pub, f.srv_random);
  CHECK(ch2_len != 0);
  sdrv_hrr_drop_x25519(ch2); /* the client ignored the HRR's group */
  CHECK(sdrv_recv_client_hello(&s, ch2, ch2_len) == 0);
  CHECK(sdrv_hrr_pending(&s) == 0); /* no second HRR armed */
  CHECK(sdrv_last_error(&s) == err_crypto(47));
}

/* Pinned real-peer ClientHello (picoquic, captured 2026-08-21 from the
 * interop runner's handshake case): key_share carries only secp256r1 while
 * supported_groups offers [secp256r1, x25519] -- the exact shape that took
 * every picoquic testcase down with a 0x128 close before the HRR path was
 * wired. It must be accepted with an HRR armed, and the built HRR must be a
 * well-formed HelloRetryRequest. */
static void test_sdrv_hrr_picoquic_client_hello_arms_hrr(void) {
  static const u8 ch[] = {
      0x01, 0x00, 0x01, 0x23, 0x03, 0x03, 0x49, 0x19, 0x15, 0x4d, 0xeb, 0xf9,
      0x3a, 0x86, 0x6a, 0xd9, 0x38, 0x0c, 0x2d, 0x42, 0x8d, 0x3c, 0x84, 0x55,
      0x8d, 0x48, 0xa7, 0x2e, 0x38, 0xe7, 0x14, 0xa8, 0xa1, 0x6a, 0x95, 0xa9,
      0x48, 0x35, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0x01,
      0x00, 0x00, 0xf4, 0x00, 0x33, 0x00, 0x47, 0x00, 0x45, 0x00, 0x17, 0x00,
      0x41, 0x04, 0x76, 0x19, 0xba, 0xec, 0x55, 0xce, 0x49, 0x1e, 0xdc, 0xf6,
      0x17, 0x7f, 0xac, 0xed, 0xb0, 0x33, 0x1c, 0x30, 0x31, 0x92, 0x5a, 0xd2,
      0x6e, 0x56, 0xf0, 0x9f, 0xb7, 0x5c, 0xa6, 0xb2, 0x38, 0x1e, 0x86, 0x3a,
      0x97, 0x96, 0xb7, 0x26, 0x28, 0x80, 0x15, 0xe8, 0xc8, 0x58, 0xa5, 0xf4,
      0x0e, 0x75, 0xca, 0x83, 0x0e, 0x63, 0xa8, 0xa0, 0x73, 0x9a, 0x03, 0xc0,
      0xc6, 0xed, 0xf3, 0xee, 0x40, 0xdd, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a,
      0x00, 0x00, 0x07, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x34, 0x00, 0x10,
      0x00, 0x0d, 0x00, 0x0b, 0x0a, 0x68, 0x71, 0x2d, 0x69, 0x6e, 0x74, 0x65,
      0x72, 0x6f, 0x70, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d,
      0x00, 0x0a, 0x00, 0x08, 0x08, 0x04, 0x04, 0x03, 0x04, 0x01, 0x02, 0x01,
      0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x1d, 0x00, 0x39,
      0x00, 0x5f, 0x05, 0x04, 0x80, 0x20, 0x00, 0x00, 0x04, 0x04, 0x80, 0x10,
      0x00, 0x00, 0x08, 0x02, 0x42, 0x00, 0x01, 0x04, 0x80, 0x02, 0xbf, 0x20,
      0x03, 0x02, 0x45, 0xa0, 0x09, 0x02, 0x42, 0x00, 0x06, 0x04, 0x80, 0x01,
      0x00, 0x63, 0x07, 0x04, 0x80, 0x00, 0xff, 0xff, 0x0e, 0x01, 0x08, 0x0b,
      0x01, 0x0a, 0x0f, 0x08, 0xff, 0x32, 0x6b, 0xf2, 0xda, 0x67, 0x4c, 0xa8,
      0x20, 0x02, 0x45, 0xfc, 0x59, 0x89, 0x04, 0x80, 0x00, 0x78, 0xdc, 0xc0,
      0x00, 0x00, 0x00, 0xff, 0x04, 0xde, 0x1b, 0x02, 0x43, 0xe8, 0x80, 0x00,
      0x71, 0x58, 0x01, 0x03, 0xc0, 0x17, 0xf7, 0x58, 0x6d, 0x2c, 0xb5, 0x71,
      0x00, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01};
  u8         hrr[256];
  sdrv       s;
  wired_obuf hob = obuf_of(hrr, sizeof(hrr));
  sdrv_hrr_init_any(&s);
  CHECK(sdrv_recv_client_hello(&s, ch, sizeof ch) == 1);
  CHECK(sdrv_hrr_pending(&s) == 1);
  CHECK(sdrv_last_error(&s) == 0);
  CHECK(sdrv_build_hrr(&s, &hob) == 1);
  CHECK(hrr_is_hello_retry(hrr, hob.len) == 1);
}

void test_sdrv_hrr(void) {
  test_sdrv_hrr_normal_ch_no_hrr_pending();
  test_sdrv_hrr_no_x25519_triggers_hrr();
  test_sdrv_hrr_second_ch_same_cipher_accepted();
  test_sdrv_hrr_second_ch_diff_cipher_rejected();
  test_sdrv_hrr_transcript_uses_message_hash();
  test_sdrv_hrr_second_ch_still_no_share_rejected();
  test_sdrv_hrr_picoquic_client_hello_arms_hrr();
}
