#include "test.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/roles/sflight/finished_build.h"

/* RFC 8446 4.4.4: the built Finished must carry verify_data that the existing
 * verifier accepts for the same key and transcript hash. */
void test_sflight_finished_build(void) {
  u8         key[HKDF_PRK];
  u8         thash[32];
  u8         out[40];
  usz        body_len;
  u8         type;
  wired_obuf ob = obuf_of(out, sizeof(out));

  for (usz i = 0; i < sizeof(key); i++) key[i] = (u8)(i + 1);
  for (usz i = 0; i < 32; i++) thash[i] = (u8)(0x80 + i);

  CHECK(sflight_finished(key, thash, &ob));
  CHECK(hs_parse(wired_span_of(out, ob.len), &type, &body_len) == 4);
  CHECK(type == HS_FINISHED);
  CHECK(body_len == TLS_VERIFY_DATA);

  /* the body is verify_data the verifier accepts. */
  CHECK(tls_finished_check(key, thash, out + 4));

  ob = obuf_of(out, 4);
  CHECK(!sflight_finished(key, thash, &ob));
}
