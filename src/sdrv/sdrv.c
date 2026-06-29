#include "sdrv/sdrv.h"
#include "shbuild/shbuild.h"
#include "sflight/certmsg.h"
#include "sflight/finished_build.h"
#include "eebuild/eebuild.h"
#include "p256cert/p256cert.h"
#include "cvecdsa/cvecdsa.h"
#include "stp/server_tp.h"
#include "p256/p256_point.h"
#include "tls/ext_keyshare.h"
#include "tls/handshake.h"
#include "tls/schedule.h"
#include "tls/x25519.h"

/* RFC 8446 4 / RFC 9001 4: drive the server handshake flight. */

static void sdrv_copy32(u8 *dst, const u8 *src)
{
    for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

/* RFC 5480 / RFC 5280 4.1: build the self-signed P-256 end-entity certificate
 * from p256_priv into the owned buffer and point the view at it. */
static void sdrv_build_cert(quic_sdrv *s)
{
    ec_point q;
    u8 pub_x[32], pub_y[32];
    quic_ec_mul(&q, s->p256_priv, &quic_p256_g);
    quic_fp_to_be(pub_x, q.x);
    quic_fp_to_be(pub_y, q.y);
    quic_p256cert_build(s->p256_priv, pub_x, pub_y,
                        s->cert_buf, sizeof(s->cert_buf), &s->cert_len);
    s->cert_der = s->cert_buf;
}

void quic_sdrv_init(quic_sdrv *s, const u8 server_priv_x25519[32],
                    const u8 server_pub_x25519[32], const u8 cert_priv[32],
                    const u8 *cert_der, usz cert_len)
{
    (void)cert_der;
    (void)cert_len;
    sdrv_copy32(s->server_priv, server_priv_x25519);
    sdrv_copy32(s->server_pub, server_pub_x25519);
    sdrv_copy32(s->p256_priv, cert_priv);
    sdrv_build_cert(s);
    s->hs_ready = 0;
    s->odcid_len = 0;
    s->iscid_len = 0;
    quic_transcript_init(&s->tr);
}

/* Copy a connection id (<=20 bytes) into dst, recording its length. Returns 1
 * on success, 0 if len exceeds 20. */
static int sdrv_set_cid(u8 *dst, u8 *dst_len, const u8 *cid, u8 len)
{
    if (len > 20) return 0;
    for (u8 i = 0; i < len; i++) dst[i] = cid[i];
    *dst_len = len;
    return 1;
}

int quic_sdrv_set_cids(quic_sdrv *s, const u8 *odcid, u8 odcid_len,
                       const u8 *iscid, u8 iscid_len)
{
    return sdrv_set_cid(s->odcid, &s->odcid_len, odcid, odcid_len)
        && sdrv_set_cid(s->iscid, &s->iscid_len, iscid, iscid_len);
}

/* RFC 8446 4.2.8: skip the client_shares(2) length, then read one KeyShareEntry
 * (group + key length + key). Returns 1 on success. */
static int client_keyshare(const u8 *d, usz dlen, u8 pub[32])
{
    if (dlen < 2) return 0;
    return quic_tls_ext_key_share_parse(d + 2, dlen - 2, pub);
}

/* One extension at q: -1 overrun, 1 key_share taken, 0 skip; *next advances. */
static int sdrv_ch_one(const u8 *b, usz q, usz end, u8 pub[32], usz *next)
{
    unsigned t = (unsigned)b[q] << 8 | b[q + 1];
    usz dlen = (usz)b[q + 2] << 8 | b[q + 3];
    if (q + 4 + dlen > end) return -1;
    *next = q + 4 + dlen;
    return (t == QUIC_EXT_KEY_SHARE) ? client_keyshare(b + q + 4, dlen, pub) : 0;
}

static int sdrv_ch_walk(const u8 *b, usz q, usz end, u8 pub[32])
{
    int r = 0;
    while (r == 0 && q + 4 <= end) r = sdrv_ch_one(b, q, end, pub, &q);
    return r == 1;
}

/* The length field of a w-byte-prefixed vector at p is in range. */
static int prefix_fits(usz p, usz w, usz n)
{
    return p != 0 && p + w <= n;
}

/* Read the w-byte big-endian length at p (w is 1 or 2). */
static usz prefix_len(const u8 *b, usz p, usz w)
{
    return w == 1 ? b[p] : ((usz)b[p] << 8 | b[p + 1]);
}

/* Skip a w-byte-length-prefixed vector at p; return the offset past it
 * (0 = overrun). */
static usz skip_vec(const u8 *b, usz n, usz p, usz w)
{
    if (!prefix_fits(p, w, n)) return 0;
    p += w + prefix_len(b, p, w);
    return p <= n ? p : 0;
}

/* RFC 8446 4.1.2: offset of the extensions-length field, or 0 on overrun. */
static usz sdrv_ch_prefix(const u8 *b, usz n)
{
    usz p = skip_vec(b, n, 34, 1);     /* session_id after version+random */
    p = skip_vec(b, n, p, 2);          /* cipher_suites */
    p = skip_vec(b, n, p, 1);          /* compression_methods */
    return prefix_fits(p, 2, n) ? p : 0;
}

/* The message is a well-framed ClientHello; sets *body_len. */
static int sdrv_is_client_hello(const u8 *buf, usz n, usz *body_len)
{
    u8 type;
    return quic_hs_parse(buf, n, &type, body_len) == 4 &&
           type == QUIC_HS_CLIENT_HELLO;
}

/* Take the client x25519 key_share from a ClientHello (header included). */
static int take_client_keyshare(const u8 *ch, usz ch_len, u8 pub[32])
{
    usz body, exts, blen;
    if (!sdrv_is_client_hello(ch, ch_len, &body)) return 0;
    exts = sdrv_ch_prefix(ch + 4, body);
    if (exts == 0) return 0;
    blen = (usz)ch[4 + exts] << 8 | ch[5 + exts];
    return sdrv_ch_walk(ch + 4, exts + 2, exts + 2 + blen, pub);
}

/* The legacy_session_id at body offset 34 is fully framed in ch_msg: the length
 * byte is present, is <=32, and its bytes all lie within ch_msg. */
static int sdrv_sid_fits(const u8 *ch_msg, usz ch_len)
{
    return ch_len >= 4 + 35 && ch_msg[4 + 34] <= 32
        && ch_len >= 4 + 35 + (usz)ch_msg[4 + 34];
}

/* RFC 8446 4.1.2: copy the ClientHello legacy_session_id (opaque<0..32> at
 * body offset 34) into the driver so ServerHello can echo it (4.1.3). Returns 1
 * on success, 0 if the field overruns ch_msg or exceeds 32 bytes. */
static int take_client_sid(quic_sdrv *s, const u8 *ch_msg, usz ch_len)
{
    u8 len;
    if (!sdrv_sid_fits(ch_msg, ch_len)) return 0;
    len = ch_msg[4 + 34];
    for (u8 i = 0; i < len; i++) s->client_sid[i] = ch_msg[4 + 35 + i];
    s->client_sid_len = len;
    return 1;
}

int quic_sdrv_recv_client_hello(quic_sdrv *s, const u8 *ch_msg, usz ch_len)
{
    if (!take_client_keyshare(ch_msg, ch_len, s->client_pub)) return 0;
    if (!take_client_sid(s, ch_msg, ch_len)) return 0;
    quic_transcript_add(&s->tr, ch_msg, ch_len);
    return 1;
}

/* Append msg[0..len) to flight at *off (cap total) and fold it into the
 * transcript. Returns 1 if it fit. */
static int emit_msg(quic_sdrv *s, const u8 *msg, usz len,
                    u8 *flight, usz cap, usz *off)
{
    if (len > cap - *off) return 0;
    for (usz i = 0; i < len; i++) flight[*off + i] = msg[i];
    *off += len;
    quic_transcript_add(&s->tr, msg, len);
    return 1;
}

/* RFC 8446 7.1: ECDHE shared secret, Handshake Secret, and the server
 * handshake traffic secret over the transcript through ServerHello (the
 * Finished's finished_key). Called right after ServerHello is folded in. */
static void derive_secret(quic_sdrv *s)
{
    u8 ecdhe[QUIC_X25519_LEN], th[QUIC_SHA256_DIGEST];
    quic_x25519(ecdhe, s->server_priv, s->client_pub);
    quic_tls_handshake_secret(ecdhe, s->hs_secret);
    quic_transcript_hash(&s->tr, th);
    quic_hkdf_expand_label(s->hs_secret, "s hs traffic", 12, th,
                           QUIC_SHA256_DIGEST, s->s_hs_traffic, QUIC_HKDF_PRK);
    s->hs_ready = 1;
}

/* RFC 8446 4.3.1 / RFC 9001 8.1-8.2: EncryptedExtensions carrying ALPN "h3"
 * and the server transport parameters, advertising the ODCID (client first
 * Initial DCID) and ISCID (server SCID) recorded via quic_sdrv_set_cids
 * (RFC 9000 7.3). */
static int emit_ee(quic_sdrv *s, u8 *flight, usz cap, usz *off)
{
    u8 tp[256], msg[1024];
    usz tn, n;
    if (!quic_stp_build_server(s->odcid, s->odcid_len, s->iscid, s->iscid_len,
                               tp, sizeof(tp), &tn)) return 0;
    if (!quic_eebuild_encrypted_extensions(tp, tn, msg, sizeof(msg), &n))
        return 0;
    return emit_msg(s, msg, n, flight, cap, off);
}

/* RFC 8446 4.4.2: build Certificate and fold it into the flight. */
static int emit_cert(quic_sdrv *s, u8 *flight, usz cap, usz *off)
{
    u8 msg[1024];
    usz n;
    if (!quic_sflight_certificate(s->cert_der, s->cert_len, msg, sizeof(msg), &n))
        return 0;
    return emit_msg(s, msg, n, flight, cap, off);
}

/* RFC 8446 4.4.3: ECDSA P-256 CertificateVerify (scheme 0x0403) over the
 * transcript through Certificate. */
static int emit_certverify(quic_sdrv *s, u8 *flight, usz cap, usz *off)
{
    u8 msg[256], th[QUIC_SHA256_DIGEST];
    usz n;
    quic_transcript_hash(&s->tr, th);
    if (!quic_cvecdsa_build(s->p256_priv, th, msg, sizeof(msg), &n))
        return 0;
    return emit_msg(s, msg, n, flight, cap, off);
}

/* RFC 8446 4.4.4: Finished under the server handshake traffic secret at the
 * transcript hash through CertificateVerify. */
static int emit_finished(quic_sdrv *s, u8 *flight, usz cap, usz *off)
{
    u8 msg[64], th[QUIC_SHA256_DIGEST];
    usz n;
    quic_transcript_hash(&s->tr, th);
    if (!quic_sflight_finished(s->s_hs_traffic, th, msg, sizeof(msg), &n))
        return 0;
    return emit_msg(s, msg, n, flight, cap, off);
}

/* RFC 8446 4.3.1 + 4.4.2: EncryptedExtensions then Certificate. */
static int emit_ee_cert(quic_sdrv *s, u8 *flight, usz cap, usz *off)
{
    return emit_ee(s, flight, cap, off) && emit_cert(s, flight, cap, off);
}

/* RFC 8446 4.4.3 + 4.4.4: CertificateVerify then Finished. */
static int emit_cv_fin(quic_sdrv *s, u8 *flight, usz cap, usz *off)
{
    return emit_certverify(s, flight, cap, off) &&
           emit_finished(s, flight, cap, off);
}

/* RFC 8446 4.4: the handshake flight after ServerHello, in order. */
static int emit_hs_flight(quic_sdrv *s, u8 *flight, usz cap, usz *off)
{
    return emit_ee_cert(s, flight, cap, off) &&
           emit_cv_fin(s, flight, cap, off);
}

/* RFC 8446 4.1.3: build the ServerHello, fold it in, and derive secrets. */
static int build_server_hello(quic_sdrv *s, const u8 *random,
                              u8 *out, usz cap, usz *len)
{
    if (!quic_shbuild_server_hello(random, s->client_sid, s->client_sid_len,
                                   0x1301, s->server_pub, out, cap, len))
        return 0;
    quic_transcript_add(&s->tr, out, *len);
    derive_secret(s);
    return 1;
}

int quic_sdrv_build_server_flight(quic_sdrv *s, const u8 *server_random,
                                  u8 *sh_out, usz sh_cap, usz *sh_len,
                                  u8 *hs_flight_out, usz hs_cap, usz *hs_len)
{
    usz off = 0;
    if (!build_server_hello(s, server_random, sh_out, sh_cap, sh_len)) return 0;
    if (!emit_hs_flight(s, hs_flight_out, hs_cap, &off)) return 0;
    *hs_len = off;
    return 1;
}

int quic_sdrv_handshake_secret(const quic_sdrv *s, const u8 **secret)
{
    if (!s->hs_ready) return 0;
    *secret = s->hs_secret;
    return 1;
}
