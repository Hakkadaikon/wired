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
  static const u8 tp[1] = {0};
  return quic_tls_client_hello(
      &(quic_clienthello_in){
          srv_random, cli_pub, quic_span_of(0, 0), quic_span_of(tp, 1)},
      &(quic_obuf){ch, cap, 0});
}

/* Overwrite the key_share group field so the ClientHello no longer offers
 * x25519 -- the only group this driver supports, so this is exactly the
 * condition quic_sdrv_recv_client_hello must recognise as "need an HRR". */
static void sdrv_hrr_drop_x25519(u8* ch) {
  ch[SDRV_HRR_KEYSHARE_GROUP_OFF]     = (u8)(QUIC_GROUP_SECP256R1 >> 8);
  ch[SDRV_HRR_KEYSHARE_GROUP_OFF + 1] = (u8)QUIC_GROUP_SECP256R1;
}

static void sdrv_hrr_set_suite(u8* ch, u16 suite) {
  ch[SDRV_HRR_CIPHER_SUITE_OFF]     = (u8)(suite >> 8);
  ch[SDRV_HRR_CIPHER_SUITE_OFF + 1] = (u8)suite;
}

static void sdrv_hrr_init_any(quic_sdrv* s) {
  u8 srv_priv[32], srv_pub[32], cert_priv[32];
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_priv[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  {
    quic_sdrv_init_in din = {srv_priv, srv_pub, cert_priv, 0, 0, 0, 0, 0};
    quic_sdrv_init(s, &din);
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
  quic_x25519_base(f->cli_pub, cli_priv);
}

/* (a) A normal ClientHello (real x25519 key_share) is accepted exactly as
 * before, with no HRR pending -- the pre-existing non-HRR path must not
 * regress. */
static void test_sdrv_hrr_normal_ch_no_hrr_pending(void) {
  sdrv_hrr_fixture f;
  u8               ch[512];
  usz              ch_len;
  quic_sdrv        s;
  sdrv_hrr_fixture_init(&f);
  ch_len = sdrv_hrr_build_ch(ch, sizeof(ch), f.cli_pub, f.srv_random);
  CHECK(ch_len != 0);
  sdrv_hrr_init_any(&s);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len) == 1);
  CHECK(quic_sdrv_hrr_pending(&s) == 0);
}

/* (b) A ClientHello offering only secp256r1 (no x25519) arms HRR, and
 * quic_sdrv_build_hrr emits a real HelloRetryRequest recognised by
 * quic_hrr_is_hello_retry. */
static void test_sdrv_hrr_no_x25519_triggers_hrr(void) {
  sdrv_hrr_fixture f;
  u8               ch[512], hrr[256];
  usz              ch_len;
  quic_sdrv        s;
  quic_obuf        hob = quic_obuf_of(hrr, sizeof(hrr));
  sdrv_hrr_fixture_init(&f);
  ch_len = sdrv_hrr_build_ch(ch, sizeof(ch), f.cli_pub, f.srv_random);
  CHECK(ch_len != 0);
  sdrv_hrr_drop_x25519(ch);
  sdrv_hrr_init_any(&s);
  CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len) == 1);
  CHECK(quic_sdrv_hrr_pending(&s) == 1);
  CHECK(quic_sdrv_build_hrr(&s, &hob) == 1);
  CHECK(quic_hrr_is_hello_retry(hrr, hob.len) == 1);
}

/* (c) A post-HRR ClientHello2 offering the same cipher_suite as
 * ClientHello1 negotiated is accepted, clearing hrr_pending again. */
static void test_sdrv_hrr_second_ch_same_cipher_accepted(void) {
  sdrv_hrr_fixture f;
  u8               ch1[512], ch2[512], hrr[256];
  usz              ch1_len, ch2_len;
  quic_sdrv        s;
  quic_obuf        hob = quic_obuf_of(hrr, sizeof(hrr));
  sdrv_hrr_fixture_init(&f);
  ch1_len = sdrv_hrr_build_ch(ch1, sizeof(ch1), f.cli_pub, f.srv_random);
  CHECK(ch1_len != 0);
  sdrv_hrr_drop_x25519(ch1);
  sdrv_hrr_init_any(&s);
  CHECK(quic_sdrv_recv_client_hello(&s, ch1, ch1_len) == 1);
  CHECK(quic_sdrv_build_hrr(&s, &hob) == 1);

  ch2_len = sdrv_hrr_build_ch(ch2, sizeof(ch2), f.cli_pub, f.srv_random);
  CHECK(ch2_len != 0);
  CHECK(quic_sdrv_recv_client_hello(&s, ch2, ch2_len) == 1);
  CHECK(quic_sdrv_hrr_pending(&s) == 0);
}

/* (d) A post-HRR ClientHello2 offering a DIFFERENT cipher_suite than
 * ClientHello1 negotiated is rejected (RFC 8446 4.1.2). */
static void test_sdrv_hrr_second_ch_diff_cipher_rejected(void) {
  sdrv_hrr_fixture f;
  u8               ch1[512], ch2[512], hrr[256];
  usz              ch1_len, ch2_len;
  quic_sdrv        s;
  quic_obuf        hob = quic_obuf_of(hrr, sizeof(hrr));
  sdrv_hrr_fixture_init(&f);
  ch1_len = sdrv_hrr_build_ch(ch1, sizeof(ch1), f.cli_pub, f.srv_random);
  CHECK(ch1_len != 0);
  sdrv_hrr_drop_x25519(ch1);
  sdrv_hrr_init_any(&s);
  CHECK(quic_sdrv_recv_client_hello(&s, ch1, ch1_len) == 1);
  CHECK(quic_sdrv_build_hrr(&s, &hob) == 1);

  ch2_len = sdrv_hrr_build_ch(ch2, sizeof(ch2), f.cli_pub, f.srv_random);
  CHECK(ch2_len != 0);
  sdrv_hrr_set_suite(ch2, QUIC_TLS_CHACHA20_POLY1305_SHA256);
  CHECK(quic_sdrv_recv_client_hello(&s, ch2, ch2_len) == 0);
}

/* (e) RFC 8446 4.4.1: after quic_sdrv_build_hrr, the transcript equals
 * Hash-chain(message_hash(Hash(ClientHello1)) || HRR), not raw
 * ClientHello1 || HRR -- proven by recomputing the expected transcript hash
 * independently and comparing to the driver's own. */
static void test_sdrv_hrr_transcript_uses_message_hash(void) {
  sdrv_hrr_fixture f;
  u8               ch1[512], hrr[256];
  usz              ch1_len;
  quic_sdrv        s;
  quic_obuf        hob = quic_obuf_of(hrr, sizeof(hrr));
  u8               ch1_hash[32], mh[36], expect[32], got[32];
  usz              mh_len;
  quic_transcript  expect_tr;

  sdrv_hrr_fixture_init(&f);
  ch1_len = sdrv_hrr_build_ch(ch1, sizeof(ch1), f.cli_pub, f.srv_random);
  CHECK(ch1_len != 0);
  sdrv_hrr_drop_x25519(ch1);
  sdrv_hrr_init_any(&s);
  CHECK(quic_sdrv_recv_client_hello(&s, ch1, ch1_len) == 1);
  CHECK(quic_sdrv_build_hrr(&s, &hob) == 1);

  quic_sha256(ch1, ch1_len, ch1_hash);
  mh_len = quic_hrr_message_hash(ch1_hash, 32, mh, sizeof(mh));
  CHECK(mh_len == 36);
  quic_transcript_init(&expect_tr);
  quic_transcript_add(&expect_tr, mh, mh_len);
  quic_transcript_add(&expect_tr, hrr, hob.len);
  quic_transcript_hash(&expect_tr, expect);
  quic_transcript_hash(&s.tr, got);
  for (int i = 0; i < 32; i++) CHECK(expect[i] == got[i]);
}

void test_sdrv_hrr(void) {
  test_sdrv_hrr_normal_ch_no_hrr_pending();
  test_sdrv_hrr_no_x25519_triggers_hrr();
  test_sdrv_hrr_second_ch_same_cipher_accepted();
  test_sdrv_hrr_second_ch_diff_cipher_rejected();
  test_sdrv_hrr_transcript_uses_message_hash();
}
