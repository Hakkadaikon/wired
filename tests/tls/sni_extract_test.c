#include "tls/ext/salpn/sni_extract.h"

#include "test.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/sni.h"

void test_sni_extract_from_clienthello(void) {
  u8         buf[512], random[32], pub[32];
  u8         tp[3] = {0x01, 0x02, 0x03};
  wired_span ext, host;
  usz        w;
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  w = tls_client_hello(
      &(clienthello_in){
          random, pub, wired_span_of((const u8*)"example.com", 11),
          wired_span_of(tp, sizeof(tp))},
      &(wired_obuf){buf, sizeof(buf), 0});
  CHECK(salpn_find_extension(wired_span_of(buf, w), SNI_TYPE, &ext));
  CHECK(salpn_extract_sni(ext, &host) == 1);
  CHECK(host.n == 11);
  CHECK(host.p[0] == 'e' && host.p[10] == 'm');
}

void test_sni_extract_truncated(void) {
  u8         list[3] = {0x00, 0x10, 0x00}; /* list_len exceeds buffer */
  wired_span host;
  CHECK(salpn_extract_sni(wired_span_of(list, sizeof(list)), &host) == 0);
  CHECK(salpn_extract_sni(wired_span_of(list, 1), &host) == 0);
}

void test_sni_extract_wrong_name_type(void) {
  /* list_len=4, name_type=0x01(not host_name), name_len=1, 'x' */
  u8         list[6] = {0x00, 0x04, 0x01, 0x00, 0x01, 'x'};
  wired_span host;
  CHECK(salpn_extract_sni(wired_span_of(list, sizeof(list)), &host) == 0);
}

/* RFC 6066 3: server_name_list<1..2^16-1> and HostName<1..2^16-1> -- an
 * empty list, an empty HostName, or bytes past the one entry are malformed,
 * never a usable name. */
void test_sni_extract_empty(void) {
  u8         empty_list[2] = {0x00, 0x00};
  u8         empty_host[5] = {0x00, 0x03, 0x00, 0x00, 0x00};
  u8         trailing[7]   = {0x00, 0x04, 0x00, 0x00, 0x01, 'x', 0xff};
  u8         ext_tail[7]   = {0x00, 0x04, 0x00, 0x00, 0x01, 'x', 0xff};
  u8         ok[6]         = {0x00, 0x04, 0x00, 0x00, 0x01, 'x'};
  wired_span host;
  CHECK(salpn_extract_sni(wired_span_of(empty_list, 2), &host) == 0);
  CHECK(salpn_extract_sni(wired_span_of(empty_host, 5), &host) == 0);
  trailing[1] = 0x05; /* list holds the entry plus one stray byte */
  CHECK(salpn_extract_sni(wired_span_of(trailing, 7), &host) == 0);
  CHECK(salpn_extract_sni(wired_span_of(ext_tail, 7), &host) == 0);
  CHECK(salpn_extract_sni(wired_span_of(ok, 6), &host) == 1);
  CHECK(host.n == 1 && host.p[0] == 'x');
}
