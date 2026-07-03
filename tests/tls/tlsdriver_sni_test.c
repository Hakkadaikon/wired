#include "test.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/ext/salpn/sni_extract.h"
#include "tls/handshake/core/tls/sni.h"
#include "tls/handshake/core/tlsdriver/tlsdriver.h"

static void sni_driver(quic_tlsdriver *d) {
  u8 priv[32], pub[32];
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(1 + i);
    pub[i]  = (u8)(0x40 + i);
  }
  quic_tlsdriver_init(d, priv, pub, 0);
}

/* RFC 6066 3: a configured server_name is carried in the raw ClientHello. */
static void test_tlsdriver_sni_present(void) {
  quic_tlsdriver d;
  u8             ch[512];
  quic_span      ext, host;
  usz            w;
  sni_driver(&d);
  quic_tlsdriver_set_sni(&d, (const u8 *)"example.com", 11);
  w = quic_tlsdriver_raw_client_hello(&d, ch, sizeof(ch));
  CHECK(w > 0);
  CHECK(
      quic_salpn_find_extension(quic_span_of(ch, w), QUIC_SNI_TYPE, &ext) == 1);
  CHECK(quic_salpn_extract_sni(ext, &host) == 1);
  CHECK(host.n == 11 && host.p[0] == 'e' && host.p[10] == 'm');
}

/* Without set_sni the extension is absent (the legacy ClientHello shape). */
static void test_tlsdriver_sni_absent(void) {
  quic_tlsdriver d;
  u8             ch[512];
  quic_span      ext;
  usz            w;
  sni_driver(&d);
  w = quic_tlsdriver_raw_client_hello(&d, ch, sizeof(ch));
  CHECK(w > 0);
  CHECK(
      quic_salpn_find_extension(quic_span_of(ch, w), QUIC_SNI_TYPE, &ext) == 0);
}

void test_tlsdriver_sni(void) {
  test_tlsdriver_sni_present();
  test_tlsdriver_sni_absent();
}
