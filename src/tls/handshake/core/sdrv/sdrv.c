#include "tls/handshake/core/sdrv/sdrv.h"

#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/pki/cert/p256cert/p256cert.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4 / RFC 9001 4: drive the server handshake flight. */

static void sdrv_copy32(u8 *dst, const u8 *src) {
  for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

/* RFC 5480 / RFC 5280 4.1: build the self-signed P-256 end-entity certificate
 * from p256_priv into the owned buffer and point the view at it. */
static void sdrv_build_cert(quic_sdrv *s) {
  ec_point q;
  u8       pub_x[32], pub_y[32];
  quic_ec_mul(&q, s->p256_priv, &quic_p256_g);
  quic_fp_to_be(pub_x, q.x);
  quic_fp_to_be(pub_y, q.y);
  quic_p256cert_key k = {s->p256_priv, pub_x, pub_y};
  quic_obuf         o = quic_obuf_of(s->cert_buf, sizeof(s->cert_buf));
  quic_p256cert_build(&k, &o);
  s->cert_len = o.len;
  s->cert_der = s->cert_buf;
}

void quic_sdrv_init(
    quic_sdrv *s,
    const u8   server_priv_x25519[32],
    const u8   server_pub_x25519[32],
    const u8   cert_priv[32],
    const u8  *cert_der,
    usz        cert_len) {
  (void)cert_der;
  (void)cert_len;
  sdrv_copy32(s->server_priv, server_priv_x25519);
  sdrv_copy32(s->server_pub, server_pub_x25519);
  sdrv_copy32(s->p256_priv, cert_priv);
  sdrv_build_cert(s);
  s->hs_ready  = 0;
  s->odcid_len = 0;
  s->iscid_len = 0;
  quic_transcript_init(&s->tr);
}

/* Copy a connection id (<=20 bytes) into dst, recording its length. Returns 1
 * on success, 0 if len exceeds 20. */
static int sdrv_set_cid(u8 *dst, u8 *dst_len, quic_span cid) {
  if (cid.n > 20) return 0;
  for (usz i = 0; i < cid.n; i++) dst[i] = cid.p[i];
  *dst_len = (u8)cid.n;
  return 1;
}

int quic_sdrv_set_cids(
    quic_sdrv *s, quic_span odcid, quic_span iscid) {
  return sdrv_set_cid(s->odcid, &s->odcid_len, odcid) &&
         sdrv_set_cid(s->iscid, &s->iscid_len, iscid);
}

/* The ClientHello extensions block being walked for the key_share. */
typedef struct {
  const u8 *b;
  usz       end;
} sdrv_ch_block;

/* One extension at *q: -1 overrun, 1 key_share taken, 0 skip; *q advances.
 * RFC 8446 4.2.8: the ClientHello key_share lists several KeyShareEntry, so
 * scan the list for x25519 rather than assuming it is the first entry. */
static int sdrv_ch_one(const sdrv_ch_block *blk, usz *q, u8 pub[32]) {
  unsigned t    = (unsigned)blk->b[*q] << 8 | blk->b[*q + 1];
  usz      dlen = (usz)blk->b[*q + 2] << 8 | blk->b[*q + 3];
  if (*q + 4 + dlen > blk->end) return -1;
  *q += 4 + dlen;
  return (t == QUIC_EXT_KEY_SHARE)
             ? quic_tls_ext_key_share_scan(blk->b + *q - dlen, dlen, pub)
             : 0;
}

static int sdrv_ch_walk(const u8 *b, usz q, usz end, u8 pub[32]) {
  sdrv_ch_block blk = {b, end};
  int           r   = 0;
  while (r == 0 && q + 4 <= end) r = sdrv_ch_one(&blk, &q, pub);
  return r == 1;
}

/* The length field of a w-byte-prefixed vector at p is in range. */
static int prefix_fits(usz p, usz w, usz n) { return p != 0 && p + w <= n; }

/* Read the w-byte big-endian length at p (w is 1 or 2). */
static usz prefix_len(const u8 *b, usz p, usz w) {
  return w == 1 ? b[p] : ((usz)b[p] << 8 | b[p + 1]);
}

/* Skip a w-byte-length-prefixed vector at p; return the offset past it
 * (0 = overrun). */
static usz skip_vec(quic_span b, usz p, usz w) {
  if (!prefix_fits(p, w, b.n)) return 0;
  p += w + prefix_len(b.p, p, w);
  return p <= b.n ? p : 0;
}

/* RFC 8446 4.1.2: offset of the extensions-length field, or 0 on overrun. */
static usz sdrv_ch_prefix(const u8 *b, usz n) {
  quic_span span = quic_span_of(b, n);
  usz       p    = skip_vec(span, 34, 1); /* session_id after version+random */
  p              = skip_vec(span, p, 2);  /* cipher_suites */
  p              = skip_vec(span, p, 1);  /* compression_methods */
  return prefix_fits(p, 2, n) ? p : 0;
}

/* The message is a well-framed ClientHello; sets *body_len. */
static int sdrv_is_client_hello(const u8 *buf, usz n, usz *body_len) {
  u8 type;
  return quic_hs_parse(quic_span_of(buf, n), &type, body_len) == 4 &&
         type == QUIC_HS_CLIENT_HELLO;
}

/* Take the client x25519 key_share from a ClientHello (header included). */
static int take_client_keyshare(const u8 *ch, usz ch_len, u8 pub[32]) {
  usz body, exts, blen;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) return 0;
  exts = sdrv_ch_prefix(ch + 4, body);
  if (exts == 0) return 0;
  blen = (usz)ch[4 + exts] << 8 | ch[5 + exts];
  return sdrv_ch_walk(ch + 4, exts + 2, exts + 2 + blen, pub);
}

/* The legacy_session_id at body offset 34 is fully framed in ch_msg: the length
 * byte is present, is <=32, and its bytes all lie within ch_msg. */
static int sdrv_sid_fits(const u8 *ch_msg, usz ch_len) {
  return ch_len >= 4 + 35 && ch_msg[4 + 34] <= 32 &&
         ch_len >= 4 + 35 + (usz)ch_msg[4 + 34];
}

/* RFC 8446 4.1.2: copy the ClientHello legacy_session_id (opaque<0..32> at
 * body offset 34) into the driver so ServerHello can echo it (4.1.3). Returns 1
 * on success, 0 if the field overruns ch_msg or exceeds 32 bytes. */
static int take_client_sid(quic_sdrv *s, const u8 *ch_msg, usz ch_len) {
  u8 len;
  if (!sdrv_sid_fits(ch_msg, ch_len)) return 0;
  len = ch_msg[4 + 34];
  for (u8 i = 0; i < len; i++) s->client_sid[i] = ch_msg[4 + 35 + i];
  s->client_sid_len = len;
  return 1;
}

int quic_sdrv_recv_client_hello(quic_sdrv *s, const u8 *ch_msg, usz ch_len) {
  if (!take_client_keyshare(ch_msg, ch_len, s->client_pub)) return 0;
  if (!take_client_sid(s, ch_msg, ch_len)) return 0;
  quic_transcript_add(&s->tr, ch_msg, ch_len);
  return 1;
}

int quic_sdrv_handshake_secret(const quic_sdrv *s, const u8 **secret) {
  if (!s->hs_ready) return 0;
  *secret = s->hs_secret;
  return 1;
}
