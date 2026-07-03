#include "tls/handshake/core/hrr/hrr_build.h"

#include "crypto/symmetric/hash/hash/sha256.h"
#include "test.h"
#include "tls/handshake/core/tls/handshake.h"

static u16 hrrt_rd16(const u8 *p) { return (u16)((p[0] << 8) | p[1]); }

/* Find extension of type `t` in the block at `ext` (total bytes); on a match
 * set *elen to its ext_data length and return a pointer to ext_data, else 0. */
static const u8 *hrr_find_ext(const u8 *ext, usz total, u16 t, usz *elen) {
  usz i = 0;
  while (i + 4 <= total) {
    usz el = hrrt_rd16(ext + i + 2);
    if (hrrt_rd16(ext + i) == t) {
      *elen = el;
      return ext + i + 4;
    }
    i += 4 + el;
  }
  return 0;
}

/* RFC 8446 4.1.3: the random sentinel is SHA-256("HelloRetryRequest"). */
static void test_hrr_random_sentinel(void) {
  u8 fixed[32];
  quic_sha256((const u8 *)"HelloRetryRequest", 17, fixed);
  for (int i = 0; i < 32; i++) CHECK(quic_hrr_random[i] == fixed[i]);
}

/* RFC 8446 4.1.4: HRR wire form without cookie. */
static void test_hrr_build_no_cookie(void) {
  u8        out[256];
  usz       len, body_len, ext_total, elen;
  u8        type;
  const u8 *body, *ext, *sv, *kse;
  quic_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_hrr_build(QUIC_GROUP_X25519, quic_span_of(0, 0), &ob) == 1);
  len = ob.len;
  CHECK(quic_hs_parse(quic_span_of(out, len), &type, &body_len) == 4);
  CHECK(type == QUIC_HS_SERVER_HELLO);

  body = out + 4;
  CHECK(hrrt_rd16(body) == 0x0303); /* legacy_version */
  for (int i = 0; i < 32; i++) CHECK(body[2 + i] == quic_hrr_random[i]);
  CHECK(body[34] == 0); /* empty session_id */
  ext       = body + 38;
  ext_total = hrrt_rd16(ext);
  ext += 2;

  sv = hrr_find_ext(ext, ext_total, QUIC_EXT_SUPPORTED_VERSIONS, &elen);
  CHECK(sv != 0 && elen == 2 && hrrt_rd16(sv) == 0x0304);

  kse = hrr_find_ext(ext, ext_total, QUIC_EXT_KEY_SHARE, &elen);
  CHECK(kse != 0 && elen == 2 && hrrt_rd16(kse) == QUIC_GROUP_X25519);

  CHECK(hrr_find_ext(ext, ext_total, 44, &elen) == 0); /* no cookie */
}

/* RFC 8446 4.2.2: cookie extension carries opaque cookie<1..2^16-1>. */
static void test_hrr_build_cookie(void) {
  u8        out[256], ck[5] = {1, 2, 3, 4, 5};
  usz       ext_total, elen;
  const u8 *ext, *c;
  quic_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_hrr_build(QUIC_GROUP_X25519, quic_span_of(ck, 5), &ob) == 1);
  ext       = out + 4 + 38;
  ext_total = hrrt_rd16(ext);
  ext += 2;
  c = hrr_find_ext(ext, ext_total, 44, &elen);
  CHECK(c != 0 && elen == 7 && hrrt_rd16(c) == 5);
  for (int i = 0; i < 5; i++) CHECK(c[2 + i] == ck[i]);
}

static void test_hrr_build_overflow(void) {
  u8        out[16];
  quic_obuf ob = quic_obuf_of(out, 8);
  CHECK(quic_hrr_build(QUIC_GROUP_X25519, quic_span_of(0, 0), &ob) == 0);
}

void test_hrr_build(void) {
  test_hrr_random_sentinel();
  test_hrr_build_no_cookie();
  test_hrr_build_cookie();
  test_hrr_build_overflow();
}
