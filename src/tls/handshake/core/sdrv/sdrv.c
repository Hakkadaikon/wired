#include "tls/handshake/core/sdrv/sdrv.h"

#include "app/datagram/datagram/datagram.h"
#include "common/diag/error/error.h"
#include "common/platform/clock/clock.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/pki/cert/p256cert/p256cert.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/ext/stp/parse_tp.h"
#include "tls/ext/tlsext/preshared.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/handshake/core/hrr/hrr_build.h"
#include "tls/handshake/core/tls/binder.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/encext_check.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/ticketfreshness.h"
#include "tls/handshake/core/tls/tpext.h"
#include "transport/conn/loop/manage/zerortt_policy.h"
#include "transport/conn/loop/manage/zerortt_seen.h"

/* RFC 8446 4 / RFC 9001 4: drive the server handshake flight. */

static void sdrv_copy32(u8* dst, const u8* src) {
  for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

/* 0 if s->san_ipv4 is all-zero (the zero-initialized default, meaning "no
 * IPv4 SAN requested" -- 0.0.0.0 is never a real peer). */
static int sdrv_has_san_ipv4(const quic_sdrv* s) {
  for (usz i = 0; i < 4; i++)
    if (s->san_ipv4[i]) return 1;
  return 0;
}

/* RFC 5480 / RFC 5280 4.1: build the self-signed P-256 end-entity certificate
 * from p256_priv into the owned buffer and record it as the 1-entry chain to
 * send. now_secs anchors the validity window (see
 * quic_sdrv_init_in.now_secs's doc). */
static void sdrv_build_cert(quic_sdrv* s, u64 now_secs) {
  ec_point q;
  u8       pub_x[32], pub_y[32];
  quic_ec_mul(&q, s->p256_priv, &quic_p256_g);
  quic_fp_to_be(pub_x, q.x);
  quic_fp_to_be(pub_y, q.y);
  {
    const u8*         ip = sdrv_has_san_ipv4(s) ? s->san_ipv4 : 0;
    quic_p256cert_key k  = {s->p256_priv, pub_x, pub_y, ip, now_secs};
    quic_obuf         o  = quic_obuf_of(s->cert_buf, sizeof(s->cert_buf));
    quic_p256cert_build(&k, &o);
    s->certs[0]   = quic_span_of(s->cert_buf, o.len);
    s->cert_count = 1;
  }
}

/* in carries a non-empty externally issued chain to use instead of a
 * self-signed certificate. */
static int sdrv_use_chain(const quic_sdrv_init_in* in) {
  return in->chain != 0 && in->chain_count != 0;
}

/* Record in->chain (leaf first) as the certificate_list to send. Over
 * QUIC_TLS_CERT_CHAIN_MAX entries fails closed: cert_count stays 0 and the
 * flight becomes unbuildable, rather than overflowing s->certs. */
static void sdrv_take_chain(quic_sdrv* s, const quic_sdrv_init_in* in) {
  if (in->chain_count > QUIC_TLS_CERT_CHAIN_MAX) {
    s->cert_count = 0;
    return;
  }
  for (usz i = 0; i < in->chain_count; i++) s->certs[i] = in->chain[i];
  s->cert_count = in->chain_count;
}

/* Copy in->san_ipv4 into s->san_ipv4[4], or zero it (the "omit" sentinel,
 * see sdrv_has_san_ipv4) when in->san_ipv4 is 0. */
static void sdrv_copy_san_ipv4(quic_sdrv* s, const u8* san_ipv4) {
  for (usz i = 0; i < 4; i++) s->san_ipv4[i] = san_ipv4 ? san_ipv4[i] : 0;
}

/* Copy in->ticket_key (QUIC_TICKET_KEY_LEN bytes) into s and record whether
 * resumption is enabled, or zero it and disable when in->ticket_key is 0. */
static void sdrv_copy_ticket_key(quic_sdrv* s, const u8* ticket_key) {
  s->has_ticket_key = ticket_key != 0;
  for (usz i = 0; i < QUIC_TICKET_KEY_LEN; i++)
    s->ticket_key[i] = ticket_key ? ticket_key[i] : 0;
}

void quic_sdrv_init(quic_sdrv* s, const quic_sdrv_init_in* in) {
  s->limits                       = (quic_stp_limits){0, 0, 0};
  s->peer_max_datagram_frame_size = 0;
  s->alpn                         = QUIC_SALPN_NONE;
  s->cipher_suite                 = QUIC_TLS_AES_128_GCM_SHA256;
  sdrv_copy32(s->server_priv, in->server_priv_x25519);
  sdrv_copy32(s->server_pub, in->server_pub_x25519);
  sdrv_copy32(s->p256_priv, in->sign_priv);
  sdrv_copy_san_ipv4(s, in->san_ipv4);
  sdrv_copy_ticket_key(s, in->ticket_key);
  if (sdrv_use_chain(in))
    sdrv_take_chain(s, in);
  else
    sdrv_build_cert(s, in->now_secs);
  s->hs_ready            = 0;
  s->odcid_len           = 0;
  s->iscid_len           = 0;
  s->tp_odcid_len        = 0;
  s->rscid_len           = 0;
  s->psk_accepted        = 0;
  s->early_data_accepted = 0;
  s->last_error          = 0;
  s->hrr_needed          = 0;
  s->hrr_sent            = 0;
  s->hrr_cipher_suite    = 0;
  for (usz i = 0; i < 32; i++) s->ch1_hash[i] = 0;
  quic_transcript_init(&s->tr);
}

/* Copy a connection id (<=20 bytes) into dst, recording its length. Returns 1
 * on success, 0 if len exceeds 20. */
static int sdrv_set_cid(u8* dst, u8* dst_len, quic_span cid) {
  if (cid.n > 20) return 0;
  for (usz i = 0; i < cid.n; i++) dst[i] = cid.p[i];
  *dst_len = (u8)cid.n;
  return 1;
}

int quic_sdrv_set_cids(quic_sdrv* s, quic_span odcid, quic_span iscid) {
  return sdrv_set_cid(s->odcid, &s->odcid_len, odcid) &&
         sdrv_set_cid(s->iscid, &s->iscid_len, iscid) &&
         sdrv_set_cid(s->tp_odcid, &s->tp_odcid_len, odcid);
}

int quic_sdrv_set_cids_retried(
    quic_sdrv* s, quic_span odcid, quic_span iscid, quic_span true_odcid) {
  return sdrv_set_cid(s->odcid, &s->odcid_len, odcid) &&
         sdrv_set_cid(s->iscid, &s->iscid_len, iscid) &&
         sdrv_set_cid(s->tp_odcid, &s->tp_odcid_len, true_odcid);
}

int quic_sdrv_set_retry_scid(quic_sdrv* s, quic_span rscid) {
  return sdrv_set_cid(s->rscid, &s->rscid_len, rscid);
}

/* The ClientHello extensions block being walked for the key_share. */
typedef struct {
  const u8* b;
  usz       end;
} sdrv_ch_block;

/* Safely read one extension's 4-byte type+length header at *q within blk and
 * advance *q past its declared extension_data. Returns 0 (and leaves *q
 * untouched) if either the header itself or its declared length would run
 * past blk->end. blk->end must already be a validated real bound (see
 * sdrv_ch_exts_span, which clamps the peer's self-reported extensions
 * length to the real ClientHello body before any walk starts); this check
 * is what stops the walk's own loop guard (q + 4 <= end) from being trusted
 * as the sole bounds check -- the loop guard alone permits reading the
 * header before confirming the header's OWN declared length also fits. */
static int sdrv_ch_hdr(
    const sdrv_ch_block* blk, usz* q, unsigned* type, usz* dlen) {
  if (*q + 4 > blk->end) return 0;
  *type = (unsigned)blk->b[*q] << 8 | blk->b[*q + 1];
  *dlen = (usz)blk->b[*q + 2] << 8 | blk->b[*q + 3];
  if (*q + 4 + *dlen > blk->end) return 0;
  *q += 4 + *dlen;
  return 1;
}

/* One extension at *q: -1 overrun, 1 key_share taken, 0 skip; *q advances.
 * RFC 8446 4.2.8: the ClientHello key_share lists several KeyShareEntry, so
 * scan the list for x25519 rather than assuming it is the first entry. */
static int sdrv_ch_keyshare_scan(const u8* d, usz dlen, u8 pub[32]) {
  usz pub_len;
  if (!quic_tls_ext_key_share_scan(
          d, dlen, QUIC_GROUP_X25519, pub, &pub_len, 32))
    return 0;
  return pub_len == 32;
}

static int sdrv_ch_one(const sdrv_ch_block* blk, usz* q, u8 pub[32]) {
  unsigned type;
  usz      dlen, start = *q;
  if (!sdrv_ch_hdr(blk, q, &type, &dlen)) return -1;
  return (type == QUIC_EXT_KEY_SHARE)
             ? sdrv_ch_keyshare_scan(blk->b + start + 4, dlen, pub)
             : 0;
}

static int sdrv_ch_walk(const u8* b, usz q, usz end, u8 pub[32]) {
  sdrv_ch_block blk = {b, end};
  int           r   = 0;
  while (r == 0 && q + 4 <= end) r = sdrv_ch_one(&blk, &q, pub);
  return r == 1;
}

/* The length field of a w-byte-prefixed vector at p is in range. */
static int prefix_fits(usz p, usz w, usz n) { return p != 0 && p + w <= n; }

/* Read the w-byte big-endian length at p (w is 1 or 2). */
static usz prefix_len(const u8* b, usz p, usz w) {
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
static usz sdrv_ch_prefix(const u8* b, usz n) {
  quic_span span = quic_span_of(b, n);
  usz       p    = skip_vec(span, 34, 1); /* session_id after version+random */
  p              = skip_vec(span, p, 2);  /* cipher_suites */
  p              = skip_vec(span, p, 1);  /* compression_methods */
  return prefix_fits(p, 2, n) ? p : 0;
}

/* The message is a well-framed ClientHello; sets *body_len. */
static int sdrv_is_client_hello(const u8* buf, usz n, usz* body_len) {
  u8 type;
  return quic_hs_parse(quic_span_of(buf, n), &type, body_len) == 4 &&
         type == QUIC_HS_CLIENT_HELLO;
}

/* Locate the ClientHello's extensions list within body (a real, already
 * length-validated ClientHello body, per quic_hs_parse): sets *start to just
 * past the 2-byte extensions-length field and *end to where the list
 * actually ends. The extensions-length field is self-reported by the peer,
 * so *end is clamped to body -- a claimed length that would run past the
 * real body is a malformed ClientHello and fails closed (0) here, rather
 * than handing an out-of-bounds *end to the walkers below. */
static int sdrv_ch_exts_span(const u8* b, usz body, usz* start, usz* end) {
  usz exts = sdrv_ch_prefix(b, body);
  usz blen;
  if (exts == 0) return 0;
  blen   = (usz)b[exts] << 8 | b[exts + 1];
  *start = exts + 2;
  *end   = *start + blen;
  return *end <= body;
}

/* Take the client x25519 key_share from a ClientHello (header included). */
static int take_client_keyshare(const u8* ch, usz ch_len, u8 pub[32]) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) return 0;
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) return 0;
  return sdrv_ch_walk(ch + 4, start, end, pub);
}

/* One extension at *q: -1 overrun, 1 if it names want_type (*ext set to its
 * full TLV, header included), 0 skip; *q advances. */
static int sdrv_ch_ext_one(
    const sdrv_ch_block* blk, usz* q, unsigned want_type, quic_span* ext) {
  unsigned type;
  usz      dlen, start = *q;
  if (!sdrv_ch_hdr(blk, q, &type, &dlen)) return -1;
  if (type != want_type) return 0;
  *ext = quic_span_of(blk->b + start, 4 + dlen);
  return 1;
}

/* Walk the same extension list as sdrv_ch_walk for one extension_type,
 * independently of the key_share scan -- a small dedicated walk rather than
 * folding unrelated searches into one function, to keep CCN low. Shared by
 * the quic_transport_parameters (RFC 9001 8.2, 0x39) and pre_shared_key
 * (RFC 8446 4.2.11, 0x0029) lookups below. */
static int sdrv_ch_find_ext(
    const u8* b, usz q, usz end, unsigned want_type, quic_span* ext) {
  sdrv_ch_block blk = {b, end};
  int           r   = 0;
  while (r == 0 && q + 4 <= end) r = sdrv_ch_ext_one(&blk, &q, want_type, ext);
  return r == 1;
}

/* Find the ClientHello's quic_transport_parameters extension_data (the raw
 * TLV, header included, as quic_tpext_decode expects). Returns 1 and sets
 * *ext on success, 0 if the ClientHello is malformed or carries no such
 * extension. */
static int find_client_tp_ext(const u8* ch, usz ch_len, quic_span* ext) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) return 0;
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) return 0;
  return sdrv_ch_find_ext(ch + 4, start, end, QUIC_TPEXT_TYPE, ext);
}

/* RFC 8446 4.2.11: locate the pre_shared_key extension (0x0029) TLV, header
 * included, if the ClientHello carries one. */
#define QUIC_SDRV_PSK_EXT_TYPE 0x0029
static int find_client_psk_ext(const u8* ch, usz ch_len, quic_span* ext) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) return 0;
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) return 0;
  return sdrv_ch_find_ext(ch + 4, start, end, QUIC_SDRV_PSK_EXT_TYPE, ext);
}

/* RFC 9221 3: extract the peer's advertised max_datagram_frame_size from the
 * ClientHello's transport parameters, if present. Leaves *out at 0 (absent /
 * unsupported) when the extension or the specific parameter is missing --
 * this is an optional parameter, never a ClientHello rejection. */
static void take_peer_max_datagram_frame_size(
    const u8* ch, usz ch_len, u64* out) {
  quic_span    ext, tp;
  quic_stp_out out_v = {out, 0};
  *out               = 0;
  if (!find_client_tp_ext(ch, ch_len, &ext)) return;
  if (quic_tpext_decode(ext, &tp) == 0) return;
  quic_stp_parse(tp, QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, &out_v);
}

/* RFC 9000 4.1/18.2: extract one integer-valued transport parameter (param_id)
 * from the ClientHello's transport parameters, if present. Leaves *out at 0
 * (absent) when the extension or the specific parameter is missing -- both
 * initial_max_data and initial_max_stream_data_bidi_local default to "send
 * nothing" when unadvertised, matching this SDK's existing absent-parameter
 * convention (take_peer_max_datagram_frame_size above). */
static void take_peer_tp_int(const u8* ch, usz ch_len, u64 param_id, u64* out) {
  quic_span    ext, tp;
  quic_stp_out out_v = {out, 0};
  *out               = 0;
  if (!find_client_tp_ext(ch, ch_len, &ext)) return;
  if (quic_tpext_decode(ext, &tp) == 0) return;
  quic_stp_parse(tp, param_id, &out_v);
}

/* The legacy_session_id at body offset 34 is fully framed in ch_msg: the length
 * byte is present, is <=32, and its bytes all lie within ch_msg. */
static int sdrv_sid_fits(const u8* ch_msg, usz ch_len) {
  return ch_len >= 4 + 35 && ch_msg[4 + 34] <= 32 &&
         ch_len >= 4 + 35 + (usz)ch_msg[4 + 34];
}

/* RFC 8446 4.1.2: copy the ClientHello legacy_session_id (opaque<0..32> at
 * body offset 34) into the driver so ServerHello can echo it (4.1.3). Returns 1
 * on success, 0 if the field overruns ch_msg or exceeds 32 bytes. */
static int take_client_sid(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  u8 len;
  if (!sdrv_sid_fits(ch_msg, ch_len)) return 0;
  len = ch_msg[4 + 34];
  for (u8 i = 0; i < len; i++) s->client_sid[i] = ch_msg[4 + 35 + i];
  s->client_sid_len = len;
  return 1;
}

/* RFC 7301 3.1/3.2: negotiate ALPN from the ClientHello's ALPN extension
 * (0x0010), preferring h3 over hq-interop (quic_salpn_negotiate). Absent or
 * malformed ALPN extension negotiates QUIC_SALPN_NONE the same as an
 * extension present but offering neither -- both fail the handshake at the
 * caller (quic_sdrv_recv_client_hello returning that outcome is not itself
 * a parse failure; the caller checks s->alpn before building a flight). */
static void sdrv_negotiate_alpn(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  quic_span ext;
  s->alpn = QUIC_SALPN_NONE;
  if (!quic_salpn_find_extension(
          quic_span_of(ch_msg, ch_len), QUIC_SALPN_EXT_TYPE, &ext))
    return;
  s->alpn = quic_salpn_negotiate(ext.p, ext.n);
}

/* The cipher_suites vector's declared byte length n at p (2-byte length
 * prefix already found by the caller) is a whole number of 2-byte suites and
 * fits within body_len. */
static int cipher_vec_ok(usz p, usz n, usz body_len) {
  return (n & 1u) == 0 && p + 2 + n <= body_len;
}

/* RFC 8446 4.1.2: the ClientHello cipher_suites vector (raw 2-byte pairs, no
 * length prefix) at body offset 34+1+session_id_len. Returns 1 and sets *out
 * on success; 0 if the ClientHello is malformed or the vector's byte length
 * is odd (not a whole number of 2-byte suites -- rejected rather than
 * silently truncated) or overruns body. */
static int sdrv_ch_cipher_suites(const u8* body, usz body_len, quic_span* out) {
  usz p = skip_vec(quic_span_of(body, body_len), 34, 1);
  usz n;
  if (!prefix_fits(p, 2, body_len)) return 0;
  n = prefix_len(body, p, 2);
  if (!cipher_vec_ok(p, n, body_len)) return 0;
  *out = quic_span_of(body + p + 2, n);
  return 1;
}

/* RFC 8446 B.4 / RFC 9001 9.3: negotiate the cipher suite from the
 * ClientHello's cipher_suites (preferring AES_128_GCM_SHA256, falling back to
 * CHACHA20_POLY1305_SHA256 -- quic_cipher_select). Returns 1 and sets
 * s->cipher_suite on success; 0 if the ClientHello is malformed, the vector
 * is not a whole number of suites, or none offered is supported (no
 * AES_128/CHACHA20 overlap) -- the caller fails the handshake rather than
 * falling back to an unconfigured suite. */
static int sdrv_negotiate_cipher(quic_sdrv* s, const u8* body, usz body_len) {
  quic_span suites;
  if (!sdrv_ch_cipher_suites(body, body_len, &suites)) return 0;
  return quic_cipher_select(suites.p, suites.n / 2, &s->cipher_suite);
}

/* The message parses as a ClientHello (sets *body) and this driver
 * negotiates a cipher suite from it (RFC 8446 B.4 / RFC 9001 9.3) -- both
 * must hold before the rest of quic_sdrv_recv_client_hello touches the
 * ClientHello's body, and both are needed before take_client_keyshare/
 * take_client_sid can run. */
static int sdrv_ch_negotiate(
    quic_sdrv* s, const u8* ch_msg, usz ch_len, usz* body) {
  if (!sdrv_is_client_hello(ch_msg, ch_len, body)) return 0;
  return sdrv_negotiate_cipher(s, ch_msg + 4, *body);
}

/* The peer-advertised fields (transport-parameter integers, ALPN) that never
 * fail the ClientHello -- absent/malformed just leaves a default and lets
 * the caller (server.c) fail later on its own terms (see each helper's doc).
 * Also folds ch_msg into the transcript (RFC 8446 4.4.1). */
static void sdrv_ch_take_optional(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  take_peer_max_datagram_frame_size(
      ch_msg, ch_len, &s->peer_max_datagram_frame_size);
  take_peer_tp_int(
      ch_msg, ch_len, QUIC_TP_INITIAL_MAX_DATA, &s->peer_initial_max_data);
  take_peer_tp_int(
      ch_msg, ch_len, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
      &s->peer_initial_max_stream_data_bidi_local);
  take_peer_tp_int(
      ch_msg, ch_len, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
      &s->peer_initial_max_stream_data_bidi_remote);
  take_peer_tp_int(
      ch_msg, ch_len, QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
      &s->peer_initial_max_stream_data_uni);
  sdrv_negotiate_alpn(s, ch_msg, ch_len);
  quic_transcript_add(&s->tr, ch_msg, ch_len);
}

/* RFC 8446 4.2.11.2: the PskBinderEntry is computed over the ClientHello
 * bytes up to and including the pre_shared_key identities list, EXCLUDING
 * the binders list itself. psk_ext is the pre_shared_key TLV located within
 * ch_msg (header included, as returned by find_client_psk_ext); id_len is
 * the single offered identity's length. Relative to the TLV start (psk_ext.p,
 * header included): the 4-byte extension header is followed by
 * identities_len(2) then one PskIdentity(2+id_len+4) -- 4+2+(2+id_len+4) =
 * 12+id_len bytes -- and the binders_len field starts right there (RFC 8446
 * 4.2.11's OfferedPsks: identities<7..>, binders<33..>). So the absolute cut
 * is psk_ext.p - ch_msg + 12 + id_len. */
static quic_span sdrv_psk_truncate(
    const u8* ch_msg, quic_span psk_ext, usz id_len) {
  usz cut = (usz)(psk_ext.p - ch_msg) + 12 + id_len;
  return quic_span_of(ch_msg, cut);
}

/* Open the presented ticket (off->identity, the sealed quic_ticket bytes)
 * under s->ticket_key. Returns 1 and fills *t on success, 0 on any failure
 * (wrong key, malformed, tampered) -- the caller degrades to a full
 * handshake rather than treating this as an error (RFC 8446 4.2.11 MAY). */
static int sdrv_psk_open_ticket(
    const quic_sdrv* s, const quic_tlsext_psk_offer* off, quic_ticket* t) {
  quic_span sealed = quic_span_of(off->identity, off->id_len);
  return quic_ticket_open(sealed, s->ticket_key, t);
}

/* RFC 8446 4.6.1: "The PSK associated with the ticket is computed as...
 * HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce,
 * Hash.length)" -- t->secret (quic_ticket's field) holds the resumption_
 * master_secret this ticket was sealed with (RFC 8446 7.1's Derive-Secret
 * output), not the PSK itself; this SDK issues every ticket with an empty
 * ticket_nonce (see newsessionticket.h), so Context is the empty span. */
static void sdrv_psk_from_ticket_secret(
    const u8 res_master_secret[QUIC_TICKET_SECRET_LEN], u8 psk_out[32]) {
  quic_hkdf_label l = {"resumption", 10, {0, 0}};
  quic_hkdf_expand_label(res_master_secret, &l, quic_mspan_of(psk_out, 32));
}

/* The opened ticket's binder verifies against the truncated ClientHello.
 * RFC 8446 4.2.11.2: a mismatch here is the hard-abort case, never a
 * fallback -- the caller must propagate 0 all the way out of
 * quic_sdrv_recv_client_hello. */
static int sdrv_psk_binder_ok(
    const quic_ticket*           t,
    const u8*                    ch_msg,
    quic_span                    psk_ext,
    const quic_tlsext_psk_offer* off) {
  quic_span truncated = sdrv_psk_truncate(ch_msg, psk_ext, off->id_len);
  u8        psk[32];
  sdrv_psk_from_ticket_secret(t->secret, psk);
  return quic_tls_binder_verify(psk, truncated, off->binder);
}

/* RFC 8446 4.2.10: locate the early_data extension (0x002a) TLV, header
 * included, if the ClientHello carries one (the body is empty in this
 * direction -- presence alone is the signal). */
#define QUIC_SDRV_EARLY_DATA_EXT_TYPE 0x002a
static int find_client_early_data_ext(
    const u8* ch, usz ch_len, quic_span* ext) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) return 0;
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) return 0;
  return sdrv_ch_find_ext(
      ch + 4, start, end, QUIC_SDRV_EARLY_DATA_EXT_TYPE, ext);
}

/* RFC 8446 8.1 / RFC 9001 9.2: single-use ticket enforcement, shared by
 * every quic_sdrv instance in this process (0-RTT replay must be caught
 * across connections, not just within one). Reused verbatim across tests in
 * this binary: a ticket identity is process-unique sealed-ciphertext bytes
 * (a fresh random nonce per quic_ticket_seal call), so unrelated tests never
 * collide on it. */
static quic_zerortt_seen g_sdrv_zerortt_seen;
static int               g_sdrv_zerortt_seen_init_done;

static quic_zerortt_seen* sdrv_zerortt_seen(void) {
  if (!g_sdrv_zerortt_seen_init_done) {
    quic_zerortt_seen_init(&g_sdrv_zerortt_seen);
    g_sdrv_zerortt_seen_init_done = 1;
  }
  return &g_sdrv_zerortt_seen;
}

/* RFC 8446 4.2.11.1 / 8.3: the ticket is on its first use (RFC 8446 8.1) and
 * the client's claimed ticket age is still fresh relative to the server's
 * own record of issuance (quic_ticket_freshness_ok) -- the two conditions
 * quic_zerortt_replay_ok's ticket_first_use argument and the freshness gate
 * this SDK adds on top of it. A stale/manipulated age is treated exactly
 * like a policy-unsafe request: 0-RTT is declined, the handshake itself
 * proceeds as 1-RTT (RFC 8446 4.2.10). */
static int sdrv_early_data_eligible(
    const quic_ticket* t, const quic_tlsext_psk_offer* off) {
  int first_use = quic_zerortt_seen_check(
      sdrv_zerortt_seen(), quic_span_of(off->identity, off->id_len));
  if (!quic_zerortt_replay_ok(1, first_use)) return 0;
  return quic_ticket_freshness_ok(t, off->ticket_age, quic_clock_epoch_secs());
}

/* RFC 8446 4.2.10: the ClientHello asked for 0-RTT (an early_data extension
 * is present) and the presented ticket is eligible (see
 * sdrv_early_data_eligible's doc). */
static int sdrv_early_data_wanted(
    const u8*                    ch_msg,
    usz                          ch_len,
    const quic_ticket*           t,
    const quic_tlsext_psk_offer* off) {
  quic_span ed_ext;
  if (!find_client_early_data_ext(ch_msg, ch_len, &ed_ext)) return 0;
  return sdrv_early_data_eligible(t, off);
}

/* RFC 8446 4.2.10 / RFC 9001 4.6.1: derive and cache the 0-RTT key/iv/hp
 * (client_early_traffic_secret) over the accepted PSK and the raw
 * ClientHello bytes -- the same inputs a peer's own 0-RTT sender used. */
static void sdrv_take_early_keys(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  quic_tls_early_keys(s->psk_secret, ch_msg, ch_len, &s->early_keys);
  s->early_data_accepted = 1;
}

/* A ticket opened under s->ticket_key: try the binder next. On a verified
 * binder, records psk_accepted/psk_secret, derives 0-RTT keys when the
 * ClientHello asked for them and the ticket is not a replay, and returns 1;
 * on a binder mismatch returns 0 (hard abort, see sdrv_psk_binder_ok's doc).
 */
static int sdrv_psk_accept_opened(
    quic_sdrv*                   s,
    const quic_ticket*           t,
    const u8*                    ch_msg,
    usz                          ch_len,
    quic_span                    psk_ext,
    const quic_tlsext_psk_offer* off) {
  if (!sdrv_psk_binder_ok(t, ch_msg, psk_ext, off)) return 0;
  s->psk_accepted = 1;
  /* s->psk_secret feeds RFC 8446 7.1's Early Secret = HKDF-Extract(0, PSK)
   * -- the actual PSK (see sdrv_psk_from_ticket_secret's doc), not the raw
   * ticket-stored resumption_master_secret. */
  sdrv_psk_from_ticket_secret(t->secret, s->psk_secret);
  if (sdrv_early_data_wanted(ch_msg, ch_len, t, off))
    sdrv_take_early_keys(s, ch_msg, ch_len);
  return 1;
}

/* A parsed pre_shared_key offer: open its ticket and, only if it opened, run
 * the binder check. A ticket that fails to open is the graceful-degrade
 * case (returns 1, psk_accepted left 0); a ticket that opens but whose
 * binder fails to verify is the hard-abort case (returns 0). */
static int sdrv_psk_try_offer(
    quic_sdrv*                   s,
    const u8*                    ch_msg,
    usz                          ch_len,
    quic_span                    psk_ext,
    const quic_tlsext_psk_offer* off) {
  quic_ticket t;
  if (!sdrv_psk_open_ticket(s, off, &t)) return 1;
  return sdrv_psk_accept_opened(s, &t, ch_msg, ch_len, psk_ext, off);
}

/* Locate and parse a pre_shared_key offer in the ClientHello, if resumption
 * is enabled and one is present. Returns 1 and fills *psk_ext and *off only
 * when both are found and well-formed; 0 otherwise (disabled, absent, or
 * malformed extension -- all "nothing to try", not an error). */
static int sdrv_find_psk_offer(
    const quic_sdrv*       s,
    const u8*              ch_msg,
    usz                    ch_len,
    quic_span*             psk_ext,
    quic_tlsext_psk_offer* off) {
  if (!s->has_ticket_key) return 0;
  if (!find_client_psk_ext(ch_msg, ch_len, psk_ext)) return 0;
  return quic_tlsext_pre_shared_key_parse(psk_ext->p, psk_ext->n, off);
}

/* RFC 8446 4.2.11: if resumption is enabled and the ClientHello carries a
 * well-formed pre_shared_key extension, try to accept it (see
 * quic_sdrv_recv_client_hello's doc for the full absent/open-fail/binder-
 * fail state table). Absent/disabled/malformed: no-op success, matching
 * today's full-handshake behavior exactly. */
static int sdrv_ch_take_psk(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  quic_span             psk_ext;
  quic_tlsext_psk_offer off;
  if (!sdrv_find_psk_offer(s, ch_msg, ch_len, &psk_ext, &off)) return 1;
  return sdrv_psk_try_offer(s, ch_msg, ch_len, psk_ext, &off);
}

/* RFC 8446 4.1.4: this driver supports only x25519 (see take_client_keyshare),
 * so "no x25519 key_share offered" is exactly the "need a HelloRetryRequest"
 * condition. Records the negotiated cipher_suite and Hash(ClientHello1) for
 * quic_sdrv_build_hrr/the post-HRR ClientHello2 check, and marks hrr_needed.
 */
static void sdrv_ch_arm_hrr(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  s->hrr_needed       = 1;
  s->hrr_cipher_suite = s->cipher_suite;
  quic_sha256(ch_msg, ch_len, s->ch1_hash);
}

/* RFC 8446 4.1.2: after a HelloRetryRequest, ClientHello2 MUST renegotiate
 * to the same cipher_suite ClientHello1 got (the client is retrying with a
 * key_share, not renegotiating algorithms). Only meaningful when
 * s->hrr_sent; sets s->last_error and returns 0 on a mismatch. */
static int sdrv_ch_retry_cipher_ok(quic_sdrv* s) {
  if (!s->hrr_sent || s->cipher_suite == s->hrr_cipher_suite) return 1;
  s->last_error = quic_err_crypto(47); /* illegal_parameter */
  return 0;
}

/* Cipher suite negotiated and (on the post-HRR ClientHello2) checked against
 * ClientHello1's. Returns 1 to keep processing, 0 on a real rejection. */
static int sdrv_ch_negotiate_cipher_gate(
    quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  usz body;
  if (!sdrv_ch_negotiate(s, ch_msg, ch_len, &body)) return 0;
  return sdrv_ch_retry_cipher_ok(s);
}

/* The client's x25519 key_share taken directly, or (its absence) recorded
 * as "HRR needed" instead of an outright rejection. Returns 1 if the caller
 * should keep processing this ClientHello as a normal (non-HRR) one, 0 if
 * HRR was armed instead (quic_sdrv_hrr_pending is now 1, not an error). */
static int sdrv_ch_keyshare_or_arm_hrr(
    quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  if (take_client_keyshare(ch_msg, ch_len, s->client_pub)) return 1;
  sdrv_ch_arm_hrr(s, ch_msg, ch_len);
  return 0;
}

/* Cipher suite negotiated (and, on the post-HRR ClientHello2, checked
 * against ClientHello1's); the client's x25519 key_share taken, or its
 * absence armed as an HRR instead of an outright rejection. */
static int sdrv_ch_negotiate_and_keyshare(
    quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  if (!sdrv_ch_negotiate_cipher_gate(s, ch_msg, ch_len)) return 0;
  return sdrv_ch_keyshare_or_arm_hrr(s, ch_msg, ch_len);
}

/* Negotiated, key_share taken, and legacy_session_id recorded -- the
 * required-field half of quic_sdrv_recv_client_hello. */
static int sdrv_ch_required_fields(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  if (!sdrv_ch_negotiate_and_keyshare(s, ch_msg, ch_len)) return 0;
  return take_client_sid(s, ch_msg, ch_len);
}

/* RFC 9001 8.2: MUST close with missing_extension (RFC 8446 B.2 alert 109)
 * when the ClientHello carries no quic_transport_parameters extension. Sets
 * s->last_error and returns 0 on that rejection, 1 otherwise. */
static int sdrv_ch_require_tp_ext(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  quic_span ext;
  int       found = find_client_tp_ext(ch_msg, ch_len, &ext);
  if (quic_encext_required_ok(found)) return 1;
  s->last_error = quic_err_crypto(109);
  return 0;
}

/* The ClientHello's TP TLV sequence (extension_data past its 4-byte header),
 * or an empty span if the extension is absent or its own framing is
 * malformed -- either case is "nothing to check here", left to the
 * individual takers elsewhere to degrade gracefully. */
static quic_span sdrv_tp_seq(const u8* ch_msg, usz ch_len) {
  quic_span ext, tp = quic_span_of(0, 0);
  if (!find_client_tp_ext(ch_msg, ch_len, &ext)) return tp;
  quic_tpext_decode(ext, &tp);
  return tp;
}

/* RFC 9000 7.4: a transport parameter id MUST NOT appear more than once. A
 * repeat is a TRANSPORT_PARAMETER_ERROR (0x08), checked once the extension
 * itself is confirmed present (sdrv_ch_require_tp_ext) and before any
 * individual parameter is read out of it. */
static int sdrv_ch_reject_dup_tp(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  quic_span tp = sdrv_tp_seq(ch_msg, ch_len);
  if (tp.n == 0 || quic_tparam_no_duplicates(tp)) return 1;
  s->last_error = QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
  return 0;
}

/* The extension gate passed and the required fields were taken -- the rest
 * of quic_sdrv_recv_client_hello (split out to keep its CCN low). */
static int sdrv_ch_after_gate(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  if (!sdrv_ch_required_fields(s, ch_msg, ch_len)) return s->hrr_needed;
  if (!sdrv_ch_take_psk(s, ch_msg, ch_len)) return 0;
  sdrv_ch_take_optional(s, ch_msg, ch_len);
  return 1;
}

int quic_sdrv_recv_client_hello(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  s->last_error = 0;
  s->hrr_needed = 0;
  if (!sdrv_ch_require_tp_ext(s, ch_msg, ch_len)) return 0;
  if (!sdrv_ch_reject_dup_tp(s, ch_msg, ch_len)) return 0;
  return sdrv_ch_after_gate(s, ch_msg, ch_len);
}

int quic_sdrv_hrr_pending(const quic_sdrv* s) { return s->hrr_needed; }

/* RFC 8446 4.4.1: replace ClientHello1 in the transcript with the synthetic
 * message_hash message (msg_type 254, body Hash(ClientHello1)) built over
 * s->ch1_hash, then fold in the just-built HRR bytes -- the transcript is
 * reset first since ClientHello1 was never folded in (sdrv_ch_arm_hrr only
 * hashed it, see its doc). */
static void sdrv_hrr_reset_transcript(
    quic_sdrv* s, const u8* hrr, usz hrr_len) {
  u8  mh[4 + 32];
  usz mh_len = quic_hrr_message_hash(s->ch1_hash, 32, mh, sizeof(mh));
  quic_transcript_init(&s->tr);
  quic_transcript_add(&s->tr, mh, mh_len);
  quic_transcript_add(&s->tr, hrr, hrr_len);
}

int quic_sdrv_build_hrr(quic_sdrv* s, quic_obuf* out) {
  if (!quic_hrr_build(QUIC_GROUP_X25519, quic_span_of(0, 0), out)) return 0;
  sdrv_hrr_reset_transcript(s, out->p, out->len);
  s->hrr_sent   = 1;
  s->hrr_needed = 0;
  return 1;
}

u64 quic_sdrv_last_error(const quic_sdrv* s) { return s->last_error; }

int quic_sdrv_handshake_secret(const quic_sdrv* s, const u8** secret) {
  if (!s->hs_ready) return 0;
  *secret = s->hs_secret;
  return 1;
}

int quic_sdrv_early_keys(const quic_sdrv* s, quic_initial_keys* out) {
  if (!s->early_data_accepted) return 0;
  *out = s->early_keys;
  return 1;
}
