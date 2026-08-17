#include "tls/handshake/core/tls/clienthello.h"

#include "common/bytes/util/be.h"
#include "tls/handshake/core/tls/alpn.h"
#include "tls/handshake/core/tls/ext_algs.h"
#include "tls/handshake/core/tls/ext_block.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/ext_versions.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/sni.h"
#include "tls/handshake/core/tls/tpext.h"

/* legacy_version(2) random(32) session_id_len(1)=0 cipher_suites(2+2)
 * compression(1+1). RFC 8446 4.1.2. */
static usz put_prefix(u8* out, usz off, const u8 random[32]) {
  be_put_be16(out + off, 0x0303);
  for (usz i = 0; i < 32; i++) out[off + 2 + i] = random[i];
  out[off + 34] = 0;
  be_put_be16(out + off + 35, 2);
  be_put_be16(out + off + 37, QUIC_TLS_AES128_GCM_SHA256);
  out[off + 39] = 1;
  out[off + 40] = 0;
  return off + 41;
}

/* Wrap body in extension_type + extension_data length and append. */
static int append_wrapped(wired_obuf* out, u16 type, wired_span body) {
  u8 hdr[4];
  be_put_be16(hdr, type);
  be_put_be16(hdr + 2, (u16)body.n);
  if (!tls_ext_append(out, wired_span_of(hdr, 4))) return 0;
  return tls_ext_append(out, body);
}

/* Encode an extension into scratch then append it whole; ANDs the room flag. */
typedef usz (*ext_enc)(u8*, usz);
static int append_self(wired_obuf* out, ext_enc enc) {
  u8  scratch[16];
  usz w = enc(scratch, sizeof(scratch));
  return (w != 0) & tls_ext_append(out, wired_span_of(scratch, w));
}

/* The mandatory extensions: supported_versions, supported_groups,
 * signature_algorithms, key_share. ks[75] fits the widest supported group
 * (secp256r1: 4 + 2 + 4 + 65). */
static int append_core(wired_obuf* out, const u8* pub, u16 group, usz pub_len) {
  u8  ks[75];
  usz kw = tls_ext_key_share(ks, sizeof(ks), group, pub, pub_len);
  int ok = append_self(out, tls_ext_supported_versions);
  ok &= append_self(out, tls_ext_supported_groups);
  ok &= append_self(out, tls_ext_sig_algs);
  return ok & (kw != 0) & tls_ext_append(out, wired_span_of(ks, kw));
}

/* server_name (RFC 6066) wrapped as ServerNameList length(2) + entry. */
static int append_sni(wired_obuf* out, wired_span sni) {
  u8         body[260];
  wired_obuf bob = obuf_of(body + 2, sizeof(body) - 2);
  usz        e;
  if (sni.n == 0) return 1;
  e = tls_sni_encode(&bob, sni);
  be_put_be16(body, (u16)e);
  return (e != 0) &
         append_wrapped(out, QUIC_SNI_TYPE, wired_span_of(body, e + 2));
}

/* ALPN offering h3 (RFC 7301). */
static int append_alpn(wired_obuf* out) {
  u8         body[16];
  wired_obuf bob = obuf_of(body, sizeof(body));
  usz        a   = tls_alpn_encode(&bob, wired_span_of((const u8*)"h3", 2));
  return (a != 0) & append_wrapped(out, QUIC_ALPN_TYPE, wired_span_of(body, a));
}

/* quic_transport_parameters (RFC 9001 8.2). */
static int append_tp(wired_obuf* out, wired_span tp) {
  u8         ext[2048];
  wired_obuf eob = obuf_of(ext, sizeof(ext));
  usz        w   = tpext_encode(&eob, tp);
  return (w != 0) & tls_ext_append(out, wired_span_of(ext, w));
}

/* Every append_* argument set beyond the shared out cursor and pub key. */
typedef struct {
  wired_span sni;
  wired_span tp;
  u16        group;
  usz        pub_len;
} clienthello_exts_in;

/* Append every extension and return the body end offset, or 0 on overflow. */
static usz append_exts(
    wired_obuf* out, const u8* pub, const clienthello_exts_in* in) {
  int ok = append_core(out, pub, in->group, in->pub_len);
  ok &= append_sni(out, in->sni);
  ok &= append_alpn(out);
  ok &= append_tp(out, in->tp);
  return ok ? out->len : 0;
}

/* Finish the extensions block at block_start and patch the handshake length. */
static usz ch_finish(u8* buf, usz off, usz block_start) {
  usz end;
  if (off == 0) return 0;
  end = tls_ext_block_finish(buf, off, block_start);
  if (end != 0) hs_finish(buf, end);
  return end;
}

/* Shared body for both entry points: build the ClientHello for random/pub
 * and the extension set in exts. */
static usz build_client_hello(
    const u8*                  random,
    const u8*                  pub,
    const clienthello_exts_in* exts,
    wired_obuf*                out) {
  usz off = hs_begin(out->p, out->cap, QUIC_HS_CLIENT_HELLO);
  usz block_start;
  if (off == 0 || off + 41 + 2 > out->cap)
    return 0; /* header + prefix + ext_len */
  off         = put_prefix(out->p, off, random);
  block_start = off;
  out->len    = off + 2;
  off         = append_exts(out, pub, exts);
  return ch_finish(out->p, off, block_start);
}

usz tls_client_hello(const clienthello_in* in, wired_obuf* out) {
  clienthello_exts_in exts = {in->sni, in->tp, QUIC_GROUP_X25519, 32};
  return build_client_hello(in->random, in->pub, &exts, out);
}

usz tls_client_hello_group(const clienthello_group_in* in, wired_obuf* out) {
  clienthello_exts_in exts = {in->sni, in->tp, in->group, in->pub_len};
  return build_client_hello(in->random, in->pub, &exts, out);
}
