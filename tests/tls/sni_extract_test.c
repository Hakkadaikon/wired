#include "tls/ext/salpn/sni_extract.h"

#include "test.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/sni.h"

void test_sni_extract_from_clienthello(void) {
  u8        buf[512], random[32], pub[32];
  u8        tp[3] = {0x01, 0x02, 0x03};
  quic_span ext, host;
  usz       w;
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  w = quic_tls_client_hello(
      &(quic_clienthello_in){
          random, pub, quic_span_of((const u8 *)"example.com", 11),
          quic_span_of(tp, sizeof(tp))},
      &(quic_obuf){buf, sizeof(buf), 0});
  CHECK(
      quic_salpn_find_extension(quic_span_of(buf, w), QUIC_SNI_TYPE, &ext));
  CHECK(quic_salpn_extract_sni(ext, &host) == 1);
  CHECK(host.n == 11);
  CHECK(host.p[0] == 'e' && host.p[10] == 'm');
}

void test_sni_extract_truncated(void) {
  u8        list[3] = {0x00, 0x10, 0x00}; /* list_len exceeds buffer */
  quic_span host;
  CHECK(quic_salpn_extract_sni(quic_span_of(list, sizeof(list)), &host) == 0);
  CHECK(quic_salpn_extract_sni(quic_span_of(list, 1), &host) == 0);
}

void test_sni_extract_wrong_name_type(void) {
  /* list_len=4, name_type=0x01(not host_name), name_len=1, 'x' */
  u8        list[6] = {0x00, 0x04, 0x01, 0x00, 0x01, 'x'};
  quic_span host;
  CHECK(quic_salpn_extract_sni(quic_span_of(list, sizeof(list)), &host) == 0);
}
