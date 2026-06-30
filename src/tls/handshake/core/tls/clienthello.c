#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/ext_block.h"
#include "tls/handshake/core/tls/ext_versions.h"
#include "tls/handshake/core/tls/ext_algs.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/sni.h"
#include "tls/handshake/core/tls/alpn.h"
#include "tls/handshake/core/tls/tpext.h"
#include "common/bytes/util/be.h"

/* legacy_version(2) random(32) session_id_len(1)=0 cipher_suites(2+2)
 * compression(1+1). RFC 8446 4.1.2. */
static usz put_prefix(u8 *out, usz off, const u8 random[32])
{
    quic_put_be16(out + off, 0x0303);
    for (usz i = 0; i < 32; i++) out[off + 2 + i] = random[i];
    out[off + 34] = 0;
    quic_put_be16(out + off + 35, 2);
    quic_put_be16(out + off + 37, QUIC_TLS_AES128_GCM_SHA256);
    out[off + 39] = 1;
    out[off + 40] = 0;
    return off + 41;
}

/* Wrap body (body_len) in extension_type + extension_data length and append. */
static int append_wrapped(u8 *buf, usz cap, usz *off, u16 type,
                          const u8 *body, usz body_len)
{
    u8 hdr[4];
    quic_put_be16(hdr, type);
    quic_put_be16(hdr + 2, (u16)body_len);
    if (!quic_tls_ext_append(buf, cap, off, hdr, 4)) return 0;
    return quic_tls_ext_append(buf, cap, off, body, body_len);
}

/* Encode an extension into scratch then append it whole; ANDs the room flag. */
typedef usz (*ext_enc)(u8 *, usz);
static int append_self(u8 *buf, usz cap, usz *off, ext_enc enc)
{
    u8 scratch[16];
    usz w = enc(scratch, sizeof(scratch));
    return (w != 0) & quic_tls_ext_append(buf, cap, off, scratch, w);
}

/* The mandatory extensions: supported_versions, supported_groups,
 * signature_algorithms, key_share. */
static int append_core(u8 *buf, usz cap, usz *off, const u8 pub[32])
{
    u8 ks[42];
    usz kw = quic_tls_ext_key_share(ks, sizeof(ks), pub);
    int ok = append_self(buf, cap, off, quic_tls_ext_supported_versions);
    ok &= append_self(buf, cap, off, quic_tls_ext_supported_groups);
    ok &= append_self(buf, cap, off, quic_tls_ext_sig_algs);
    return ok & (kw != 0) & quic_tls_ext_append(buf, cap, off, ks, kw);
}

/* server_name (RFC 6066) wrapped as ServerNameList length(2) + entry. */
static int append_sni(u8 *buf, usz cap, usz *off, const u8 *sni, usz sni_len)
{
    u8 body[260];
    usz e;
    if (sni_len == 0) return 1;
    e = quic_tls_sni_encode(body + 2, sizeof(body) - 2, sni, sni_len);
    quic_put_be16(body, (u16)e);
    return (e != 0) & append_wrapped(buf, cap, off, QUIC_SNI_TYPE, body, e + 2);
}

/* ALPN offering h3 (RFC 7301). */
static int append_alpn(u8 *buf, usz cap, usz *off)
{
    u8 body[16];
    usz a = quic_tls_alpn_encode(body, sizeof(body), (const u8 *)"h3", 2);
    return (a != 0) & append_wrapped(buf, cap, off, QUIC_ALPN_TYPE, body, a);
}

/* quic_transport_parameters (RFC 9001 8.2). */
static int append_tp(u8 *buf, usz cap, usz *off, const u8 *tp, usz tp_len)
{
    u8 ext[2048];
    usz w = quic_tpext_encode(ext, sizeof(ext), tp, tp_len);
    return (w != 0) & quic_tls_ext_append(buf, cap, off, ext, w);
}

/* Append every extension and return the body end offset, or 0 on overflow. */
static usz append_exts(u8 *buf, usz cap, usz off, const u8 pub[32],
                       const u8 *sni, usz sni_len, const u8 *tp, usz tp_len)
{
    int ok = append_core(buf, cap, &off, pub);
    ok &= append_sni(buf, cap, &off, sni, sni_len);
    ok &= append_alpn(buf, cap, &off);
    ok &= append_tp(buf, cap, &off, tp, tp_len);
    return ok ? off : 0;
}

/* Finish the extensions block at block_start and patch the handshake length. */
static usz ch_finish(u8 *buf, usz off, usz block_start)
{
    usz end;
    if (off == 0) return 0;
    end = quic_tls_ext_block_finish(buf, off, block_start);
    if (end != 0) quic_hs_finish(buf, end);
    return end;
}

usz quic_tls_client_hello(u8 *buf, usz cap, const u8 random[32],
                          const u8 pub[32], const u8 *sni, usz sni_len,
                          const u8 *tp, usz tp_len)
{
    usz off = quic_hs_begin(buf, cap, QUIC_HS_CLIENT_HELLO);
    usz block_start;
    if (off == 0 || off + 41 + 2 > cap) return 0;  /* header + prefix + ext_len */
    off = put_prefix(buf, off, random);
    block_start = off;
    off = append_exts(buf, cap, off + 2, pub, sni, sni_len, tp, tp_len);
    return ch_finish(buf, off, block_start);
}
