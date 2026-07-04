#include "crypto/asymmetric/ecc/cvecdsa/signed.h"

/* RFC 8446 4.4.3 server context string, sans terminating NUL. */
static const char cvec_ctx[] = "TLS 1.3, server CertificateVerify";

static void cvec_fill_pad(u8* out) {
  for (usz i = 0; i < 64; i++) out[i] = 0x20;
}

static void cvec_put_ctx(u8* out) {
  for (usz i = 0; i < 33; i++) out[i] = (u8)cvec_ctx[i];
}

static void cvec_put_hash(u8* out, const u8* transcript_hash) {
  for (usz i = 0; i < 32; i++) out[i] = transcript_hash[i];
}

void quic_cvecdsa_signed_content(const u8 transcript_hash[32], u8 out[130]) {
  cvec_fill_pad(out);
  cvec_put_ctx(out + 64);
  out[97] = 0x00;
  cvec_put_hash(out + 98, transcript_hash);
}
