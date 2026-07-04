#include "tls/handshake/roles/sflight/certverify_build.h"

#include "common/bytes/util/be.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "tls/handshake/core/tls/handshake.h"

#define QUIC_HS_CERTIFICATE_VERIFY 15
#define QUIC_SFLIGHT_SCHEME_ED25519 0x0807

/* RFC 8446 4.4.3 server context string, sans terminating NUL. */
static const char cv_ctx[] = "TLS 1.3, server CertificateVerify";

static void cvb_fill_pad(u8* out) {
  for (usz i = 0; i < 64; i++) out[i] = 0x20;
}

static void cvb_put_ctx(u8* out) {
  for (usz i = 0; i < 33; i++) out[i] = (u8)cv_ctx[i];
}

static void cvb_put_hash(u8* out, const u8* transcript_hash) {
  for (usz i = 0; i < 32; i++) out[i] = transcript_hash[i];
}

/* 64*0x20 + ctx(33) + 0x00 + transcript_hash(32) = 130 octets. */
static void sflight_cv_signed(const u8* transcript_hash, u8 out[130]) {
  cvb_fill_pad(out);
  cvb_put_ctx(out + 64);
  out[97] = 0x00;
  cvb_put_hash(out + 98, transcript_hash);
}

int quic_sflight_certificate_verify(
    const u8 seed[32], const u8* transcript_hash, quic_obuf* out) {
  u8  content[130];
  usz off;
  if (out->cap < 4 + 2 + 2 + QUIC_ED25519_SIG) return 0;
  off = quic_hs_begin(out->p, out->cap, QUIC_HS_CERTIFICATE_VERIFY);
  sflight_cv_signed(transcript_hash, content);
  quic_put_be16(out->p + off, QUIC_SFLIGHT_SCHEME_ED25519);
  quic_put_be16(out->p + off + 2, QUIC_ED25519_SIG);
  quic_ed25519_sign(seed, content, 130, out->p + off + 4);
  out->len = off + 4 + QUIC_ED25519_SIG;
  quic_hs_finish(out->p, out->len);
  return 1;
}
