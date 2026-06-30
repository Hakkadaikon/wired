#include "tls/ext/salpn/sni_extract.h"

#include "test.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/sni.h"

void test_sni_extract_from_clienthello(void) {
  u8        buf[512], random[32], pub[32];
  u8        tp[3] = {0x01, 0x02, 0x03};
  const u8 *data, *host;
  usz       dlen, hlen, w;
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  w = quic_tls_client_hello(
      buf, sizeof(buf), random, pub, (const u8 *)"example.com", 11, tp,
      sizeof(tp));
  CHECK(quic_salpn_find_extension(buf, w, QUIC_SNI_TYPE, &data, &dlen));
  CHECK(quic_salpn_extract_sni(data, dlen, &host, &hlen) == 1);
  CHECK(hlen == 11);
  CHECK(host[0] == 'e' && host[10] == 'm');
}

void test_sni_extract_truncated(void) {
  u8        list[3] = {0x00, 0x10, 0x00}; /* list_len exceeds buffer */
  const u8 *host;
  usz       hlen;
  CHECK(quic_salpn_extract_sni(list, sizeof(list), &host, &hlen) == 0);
  CHECK(quic_salpn_extract_sni(list, 1, &host, &hlen) == 0);
}

void test_sni_extract_wrong_name_type(void) {
  /* list_len=4, name_type=0x01(not host_name), name_len=1, 'x' */
  u8        list[6] = {0x00, 0x04, 0x01, 0x00, 0x01, 'x'};
  const u8 *host;
  usz       hlen;
  CHECK(quic_salpn_extract_sni(list, sizeof(list), &host, &hlen) == 0);
}
