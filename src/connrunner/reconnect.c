#include "connrunner/reconnect.h"
#include "retrydrive/accept.h"
#include "retrydrive/token.h"
#include "vndrive/accept.h"
#include "vndrive/select.h"
#include "vndrive/reconnect.h"
#include "tls/handshake/core/handshake_drive/retry_drive.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/packet/header/packet/vneg.h"
#include "tls/handshake/core/tls/initial.h"
#include "crypto/kdf/keys/keyset.h"
#include "version/version.h"
#include "common/bytes/util/bytes.h"

void quic_connrunner_reconnect_init(quic_connrunner *r)
{
    r->retry.received = 0;
    r->retry.key_rederive = 0;
    r->retry.token_len = 0;
    r->retry.dcid_len = 0;
    r->vn_retry_count = 0;
}

/* RFC 9000 17.2.5.2: the handshake must not have progressed and the Retry
 * (first, valid tag) must be accepted; the compound lives here. */
static int retry_ok(const quic_connrunner *r, int tag_valid)
{
    return !r->io.loop.handshake_complete
        && quic_retrydrive_accept(r->retry.received, tag_valid);
}

int quic_connrunner_recv_retry(quic_connrunner *r, int tag_valid,
                               const u8 *scid, usz scid_len,
                               const u8 *token, usz token_len)
{
    if (!retry_ok(r, tag_valid)) return 0;
    return quic_retrydrive_apply(token, token_len, scid, scid_len, &r->retry);
}

/* RFC 9001 5.2: install the new Initial keys derived from the Retry DCID and
 * adopt that DCID for subsequent Initials. */
static void rederive_initial(quic_connrunner *r)
{
    quic_initial_keys k;
    usz off = 0;
    quic_initial_derive(r->retry.dcid, r->retry.dcid_len, r->io.loop.is_server,
                        &k);
    quic_keyset_install(&r->io.loop.keys, QUIC_LEVEL_INITIAL, &k);
    quic_put_bytes(r->io.dcid, sizeof r->io.dcid, &off, r->retry.dcid,
                   r->retry.dcid_len);
    r->io.dcid_len = r->retry.dcid_len;
}

int quic_connrunner_retry_rederive(quic_connrunner *r)
{
    if (!r->retry.key_rederive) return 0;
    rederive_initial(r);
    r->retry.key_rederive = 0; /* RFC 9001 5.2: keys now match the new DCID */
    return 1;
}

void quic_connrunner_initial_token(const quic_connrunner *r,
                                   const u8 **token, usz *len)
{
    quic_retrydrive_initial_token(&r->retry, token, len);
}

/* RFC 9000 6.2: a VN is processed only before the handshake progresses and when
 * it is not a downgrade (sent version absent from the offered list). */
static int vn_ok(const quic_connrunner *r, const u32 *offered, usz n_off)
{
    return !r->io.loop.handshake_complete
        && quic_vndrive_accept(r->io.loop.handshake_complete, r->sent_version,
                               offered, n_off);
}

/* RFC 9000 6.2: with a common version chosen, reconnect once within budget;
 * returns 1 (count incremented) or 0 when the single VN retry is spent. */
static int vn_reconnect(quic_connrunner *r, u32 chosen)
{
    if (!quic_vndrive_should_retry(chosen, r->vn_retry_count)) return 0;
    r->vn_retry_count++;
    return 1;
}

int quic_connrunner_recv_vn(quic_connrunner *r, const u32 *offered, usz n_off,
                            const u32 *supported, usz n_sup, u32 *chosen)
{
    if (!vn_ok(r, offered, n_off)) return 0; /* downgrade or after progress */
    if (!quic_vndrive_select(offered, n_off, supported, n_sup, chosen))
        return QUIC_CONNRUNNER_VN_ABORT; /* RFC 9000 6.2: no common version */
    return vn_reconnect(r, *chosen);
}

/* RFC 9000 6.2: the client's supported versions in preference order. */
static const u32 g_supported[2] = { QUIC_VERSION_2, QUIC_VERSION_1 };

/* Read the i-th offered version (4 big-endian bytes) from a VN list view. */
static u32 vn_version_at(const u8 *versions, usz i)
{
    const u8 *p = versions + i * 4;
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

/* Copy up to QUIC_VERS_OFFERED offered versions out of the parsed VN view. */
#define QUIC_VERS_OFFERED 16
static usz vn_offered(const quic_vneg_packet *v, u32 *out)
{
    usz n = v->count < QUIC_VERS_OFFERED ? v->count : QUIC_VERS_OFFERED;
    for (usz i = 0; i < n; i++) out[i] = vn_version_at(v->versions, i);
    return n;
}

/* RFC 9000 6.2: parse a Version Negotiation packet and drive recv_vn over its
 * offered list; a malformed packet is consumed (1) without action. */
static int drive_vn(quic_connrunner *r, const u8 *pkt, usz len)
{
    quic_vneg_packet v;
    u32 offered[QUIC_VERS_OFFERED], chosen;
    if (quic_vneg_parse(pkt, len, &v) == 0) return 1;
    quic_connrunner_recv_vn(r, offered, vn_offered(&v, offered),
                            g_supported, 2, &chosen);
    return 1;
}

/* RFC 9000 17.2.5: parse and verify a Retry against the current DCID, then
 * drive recv_retry; a malformed Retry is consumed (1) without action. */
static int drive_retry(quic_connrunner *r, const u8 *pkt, usz len)
{
    u8 token[256], dcid[QUIC_MAX_CID_LEN];
    usz tlen;
    u8 dlen;
    int valid = quic_retry_process(pkt, len, r->io.dcid, r->io.dcid_len,
                                   token, &tlen, dcid, &dlen);
    quic_connrunner_recv_retry(r, valid, dcid, dlen, token, tlen);
    return 1;
}

/* RFC 8999 5.1: a Version field of 0 marks a Version Negotiation packet. */
static int vneg_version_zero(const u8 *pkt)
{
    return (pkt[1] | pkt[2] | pkt[3] | pkt[4]) == 0;
}

static int is_vneg(const u8 *pkt, usz len)
{
    return len >= 5 && vneg_version_zero(pkt);
}

/* Route a long-header packet that is a Retry or VN; 0 if it is neither. */
static int drive_long(quic_connrunner *r, const u8 *pkt, usz len)
{
    if (is_vneg(pkt, len)) return drive_vn(r, pkt, len);
    if (quic_packet_long_type(pkt[0]) == QUIC_PT_RETRY)
        return drive_retry(r, pkt, len);
    return 0;
}

int quic_connrunner_recv_reconnect(quic_connrunner *r, const u8 *pkt, usz len)
{
    if (!quic_packet_is_long(pkt[0])) return 0;
    return drive_long(r, pkt, len);
}
