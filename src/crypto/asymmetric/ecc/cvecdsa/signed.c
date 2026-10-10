#include "crypto/asymmetric/ecc/cvecdsa/signed.h"

/* RFC 8446 4.4.3 server context string, sans terminating NUL. */
static const char cvec_ctx[] = "TLS 1.3, server CertificateVerify";

static void cvec_fill_pad(u8* out) {
  for (usz i = 0; i < 64; i++) out[i] = 0x20;
}

static void cvec_put_ctx(u8* out) {
  for (usz i = 0; i < 33; i++) out[i] = (u8)cvec_ctx[i];
}

static void cvec_put_hash(u8* out, wired_span transcript_hash) {
  for (usz i = 0; i < transcript_hash.n; i++) out[i] = transcript_hash.p[i];
}

usz cvecdsa_signed_content(wired_span transcript_hash, u8* out) {
  cvec_fill_pad(out);
  cvec_put_ctx(out + 64);
  out[97] = 0x00;
  cvec_put_hash(out + 98, transcript_hash);
  return 98 + transcript_hash.n;
}
