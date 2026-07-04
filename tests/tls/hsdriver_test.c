#include "tls/handshake/core/tls/hsdriver.h"

#include "test.h"

/* Drive the legal client-side flight up to (but not including) the message at
 * index `stop`. Asserts every step is accepted; verifies cert before the
 * peer's Finished so the auth gate is open. */
static void drive_until(quic_hsdriver* s, int stop) {
  if (stop > 0) CHECK(quic_hsdriver_recv(s, QUIC_HSD_CLIENT_HELLO, 0) == 1);
  if (stop > 1) CHECK(quic_hsdriver_recv(s, QUIC_HSD_SERVER_HELLO, 0) == 1);
  if (stop > 2) CHECK(quic_hsdriver_recv(s, QUIC_HSD_ENCRYPTED_EXT, 1) == 1);
  if (stop > 3) CHECK(quic_hsdriver_recv(s, QUIC_HSD_CERTIFICATE, 1) == 1);
  if (stop > 4) CHECK(quic_hsdriver_recv(s, QUIC_HSD_CERT_VERIFY, 1) == 1);
  if (stop > 5) quic_hsdriver_cert_verified(s);
  if (stop > 5) CHECK(quic_hsdriver_recv(s, QUIC_HSD_FINISHED, 1) == 1);
}

/* RFC 8446 4: server flight may not begin before ClientHello is received. */
static void test_server_does_not_send_before_clienthello(void) {
  quic_hsdriver s;
  quic_hsdriver_init(&s, 1);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_SERVER_HELLO, 0) == 0);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_ENCRYPTED_EXT, 1) == 0);
  /* once ClientHello lands, ServerHello is accepted */
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_CLIENT_HELLO, 0) == 1);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_SERVER_HELLO, 0) == 1);
}

/* RFC 8446 4.4.2/4.4.3: server Finished is rejected until Certificate and
 * CertificateVerify are verified. */
static void test_server_finished_rejected_before_auth(void) {
  quic_hsdriver s;
  quic_hsdriver_init(&s, 0);
  drive_until(&s, 5); /* CH..CV accepted, but cert NOT marked verified */
  CHECK(s.cert_verified == 0);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_FINISHED, 1) == 0);
  /* after verification it is accepted */
  quic_hsdriver_cert_verified(&s);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_FINISHED, 1) == 1);
}

/* RFC 9001 4: keys promote Initial -> Handshake -> 1-RTT, no skipping. */
static void test_keys_promote_in_strict_order(void) {
  quic_hsdriver s;
  quic_hsdriver_init(&s, 0);
  /* a Handshake-level message before any Initial-level one is rejected */
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_ENCRYPTED_EXT, 1) == 0);
  /* the legal flight promotes the level monotonically */
  quic_hsdriver_init(&s, 0);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_CLIENT_HELLO, 0) == 1);
  CHECK(s.level == QUIC_HSD_PROT_INITIAL);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_SERVER_HELLO, 0) == 1);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_ENCRYPTED_EXT, 1) == 1);
  CHECK(s.level == QUIC_HSD_PROT_HANDSHAKE);
  /* a 1-RTT message cannot arrive while still at Handshake mid-flight */
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_HANDSHAKE_DONE, 2) == 0);
}

/* Each message must be carried at exactly its defined level (RFC 9001 4). */
static void test_message_carried_at_defined_level(void) {
  quic_hsdriver s;
  quic_hsdriver_init(&s, 0);
  /* ClientHello at Handshake level is wrong */
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_CLIENT_HELLO, 1) == 0);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_CLIENT_HELLO, 0) == 1);
  /* EncryptedExtensions at Initial level is wrong */
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_SERVER_HELLO, 0) == 1);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_ENCRYPTED_EXT, 0) == 0);
}

/* RFC 8446 4.4: CertificateVerify may not precede Certificate; no forward
 * jump over a flight message. */
static void test_out_of_order_rejected(void) {
  quic_hsdriver s;
  quic_hsdriver_init(&s, 0);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_CLIENT_HELLO, 0) == 1);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_SERVER_HELLO, 0) == 1);
  /* jump past EE/Cert straight to CertificateVerify */
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_CERT_VERIFY, 1) == 0);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_ENCRYPTED_EXT, 1) == 1);
  /* CertificateVerify before Certificate */
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_CERT_VERIFY, 1) == 0);
}

/* not confirmed before complete; confirmed implies complete (RFC 9001 4.1.2).
 */
static void test_not_confirmed_before_complete(void) {
  quic_hsdriver s;
  quic_hsdriver_init(&s, 0);
  drive_until(&s, 6); /* full flight through peer Finished */
  CHECK(quic_hsdriver_complete(&s) == 1);
  CHECK(quic_hsdriver_confirmed(&s) == 0);
  /* HANDSHAKE_DONE cannot be accepted before complete */
  quic_hsdriver s2;
  quic_hsdriver_init(&s2, 0);
  drive_until(&s2, 5);
  quic_hsdriver_cert_verified(&s2);
  CHECK(quic_hsdriver_recv(&s2, QUIC_HSD_HANDSHAKE_DONE, 2) == 0);
  CHECK(quic_hsdriver_confirmed(&s2) == 0);
}

/* happy path reaches complete then confirmed (RFC 8446 4 / RFC 9001 4.1.2). */
static void test_full_handshake_reaches_confirmed(void) {
  quic_hsdriver s;
  quic_hsdriver_init(&s, 0);
  drive_until(&s, 6);
  CHECK(quic_hsdriver_complete(&s) == 1);
  CHECK(quic_hsdriver_recv(&s, QUIC_HSD_HANDSHAKE_DONE, 2) == 1);
  CHECK(quic_hsdriver_confirmed(&s) == 1);
  CHECK(quic_hsdriver_complete(&s) == 1);
}

void test_hsdriver(void) {
  test_server_does_not_send_before_clienthello();
  test_server_finished_rejected_before_auth();
  test_keys_promote_in_strict_order();
  test_message_carried_at_defined_level();
  test_out_of_order_rejected();
  test_not_confirmed_before_complete();
  test_full_handshake_reaches_confirmed();
}

#ifdef HSDRIVER_TEST_MAIN
int main(void) {
  test_hsdriver();
  return TEST_REPORT();
}
#endif
