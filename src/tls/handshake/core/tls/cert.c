#include "tls/handshake/core/tls/cert.h"

#include "crypto/asymmetric/ecc/ed25519/ed25519.h"

/* TLS uses fixed big-endian length prefixes. A small cursor reads them and
 * bounds every access against the message end. */
typedef struct {
  const u8* b;
  usz       n;
  usz       off;
} cur;

/* Read a k-byte (1..3) big-endian length into *v. Returns 1 if it fits. */
static int take_len(cur* c, usz k, u32* v) {
  if (c->off + k > c->n) return 0;
  *v = 0;
  for (usz i = 0; i < k; i++) *v = (*v << 8) | c->b[c->off + i];
  c->off += k;
  return 1;
}

/* Take a view of len bytes at the cursor. Returns 1 if it fits. */
static int take_view(cur* c, u32 len, const u8** out) {
  if (c->off + len > c->n) return 0;
  *out = c->b + c->off;
  c->off += len;
  return 1;
}

/* Read a k-byte length then that many bytes as a view. */
static int take_vec(cur* c, usz k, quic_span* out) {
  u32       len;
  const u8* p;
  if (!take_len(c, k, &len)) return 0;
  if (!take_view(c, len, &p)) return 0;
  *out = quic_span_of(p, len);
  return 1;
}

/* The end-entity entry: cert_data (3-byte length) then its extensions
 * (2-byte length), within the certificate_list. */
static int take_entry(cur* c, quic_tls_cert_entry* first) {
  quic_span cert, ext;
  if (!take_vec(c, 3, &cert)) return 0;
  if (!take_vec(c, 2, &ext)) return 0; /* skip this entry's extensions */
  first->cert_data = cert.p;
  first->cert_len  = (u32)cert.n;
  return 1;
}

int quic_tls_cert_parse(
    quic_span buf, quic_span* context, quic_tls_cert_entry* first) {
  cur       c = {buf.p, buf.n, 0};
  quic_span list;
  cur       lc;
  if (!take_vec(&c, 1, context)) return 0;
  if (!take_vec(&c, 3, &list)) return 0;
  lc = (cur){list.p, list.n, 0};
  return take_entry(&lc, first); /* first entry is the end-entity cert */
}

/* One more entry into out->entries[*out->count], bounded by out->cap (fail
 * closed on overflow). */
static int take_next(cur* lc, const quic_tls_cert_chain_out* out) {
  if (*out->count >= out->cap) return 0;
  if (!take_entry(lc, &out->entries[*out->count])) return 0;
  (*out->count)++;
  return 1;
}

/* Every entry of the certificate_list, leaf first. */
static int entries_loop(cur* lc, const quic_tls_cert_chain_out* out) {
  while (lc->off < lc->n)
    if (!take_next(lc, out)) return 0;
  return 1;
}

int quic_tls_cert_chain(
    quic_span buf, quic_span* context, const quic_tls_cert_chain_out* out) {
  cur       c = {buf.p, buf.n, 0};
  quic_span list;
  cur       lc;
  *out->count = 0;
  if (!take_vec(&c, 1, context)) return 0;
  if (!take_vec(&c, 3, &list)) return 0;
  lc = (cur){list.p, list.n, 0};
  return entries_loop(&lc, out);
}

int quic_tls_certverify_parse(quic_span buf, u16* scheme, quic_span* sig) {
  cur c = {buf.p, buf.n, 0};
  u32 s;
  if (!take_len(&c, 2, &s)) return 0;
  if (!take_vec(&c, 2, sig)) return 0;
  *scheme = (u16)s;
  return 1;
}

/* The RFC 8446 4.4.3 server context string, sans terminating NUL. */
static const char ctx_str[] = "TLS 1.3, server CertificateVerify";

/* Copy len bytes from src to dst. */
static void cert_copy_bytes(u8* dst, const u8* src, usz len) {
  for (usz i = 0; i < len; i++) dst[i] = src[i];
}

static const u8 pad64[64] = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

/* Build the 130-byte signed content into out (64 pad + 33 context + 1 sep +
 * 32 hash). */
static void build_signed(const u8 transcript_hash[32], u8 out[130]) {
  cert_copy_bytes(out, pad64, 64);
  cert_copy_bytes(out + 64, (const u8*)ctx_str, 33);
  out[97] = 0x00;
  cert_copy_bytes(out + 98, transcript_hash, 32);
}

int quic_tls_certverify_ed25519(
    quic_span sig, const u8 transcript_hash[32], const u8 pubkey[32]) {
  u8 content[130];
  if (sig.n != QUIC_ED25519_SIG) return 0;
  build_signed(transcript_hash, content);
  return quic_ed25519_verify(sig.p, content, sizeof(content), pubkey);
}
