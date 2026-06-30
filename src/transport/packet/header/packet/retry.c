#include "transport/packet/header/packet/retry.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* Append a length-prefixed CID at *off; returns 1 ok, 0 if no room. */
static int retry_put_cid(u8 *buf, usz cap, usz *off, const u8 *cid, u8 len)
{
    if (*off + 1 + (usz)len > cap) return 0;
    buf[*off] = len;
    *off += 1;
    return quic_put_bytes(buf, cap, off, cid, len);
}

/* True if the whole Retry packet fits in cap. */
static int retry_fits(usz cap, u8 dcid_len, u8 scid_len, usz token_len)
{
    usz need = 5 + 1 + (usz)dcid_len + 1 + (usz)scid_len + token_len +
               QUIC_RETRY_TAG_LEN;
    return need <= cap;
}

usz quic_retry_build(u8 *buf, usz cap, u32 version,
                     const u8 *dcid, u8 dcid_len, const u8 *scid, u8 scid_len,
                     const u8 *token, usz token_len, const u8 *tag)
{
    usz off = 5;
    if (!retry_fits(cap, dcid_len, scid_len, token_len)) return 0;
    buf[0] = 0xF0; /* RFC 9000 17.2.5: long form, fixed bit, type Retry (0x3) */
    quic_put_be32(buf + 1, version);
    retry_put_cid(buf, cap, &off, dcid, dcid_len); /* room checked above */
    retry_put_cid(buf, cap, &off, scid, scid_len);
    quic_put_bytes(buf, cap, &off, token, token_len);
    quic_put_bytes(buf, cap, &off, tag, QUIC_RETRY_TAG_LEN);
    return off;
}

/* Read a length-prefixed CID at *off into dst/dst_len; 1 ok, 0 truncated. */
static int retry_take_cid(const u8 *buf, usz n, usz *off, u8 *dst, u8 *dst_len)
{
    u8 len;
    if (*off >= n) return 0;
    len = buf[*off];
    if (len > QUIC_MAX_CID_LEN) return 0;
    *off += 1;
    *dst_len = len;
    return quic_take_bytes(buf, n, off, dst, len);
}

/* True if a long-form Retry byte0 with a token of >= 0 bytes can follow. */
static int retry_head_ok(const u8 *buf, usz n)
{
    if (n < 5 + 1 + 1 + QUIC_RETRY_TAG_LEN) return 0;
    return (buf[0] & 0xF0) == 0xF0;
}

/* Read both CIDs at *off; returns 1 ok, 0 if either is truncated. */
static int retry_take_cids(const u8 *buf, usz n, usz *off, quic_retry_packet *r)
{
    if (!retry_take_cid(buf, n, off, r->dcid, &r->dcid_len)) return 0;
    return retry_take_cid(buf, n, off, r->scid, &r->scid_len);
}

/* With CIDs consumed up to off, split the remainder into token + tag.
 * Returns 1 ok, 0 if no room is left for the 16-byte tag. */
static int take_token_tag(const u8 *buf, usz n, usz off, quic_retry_packet *r)
{
    usz tag_off = n - QUIC_RETRY_TAG_LEN;
    if (off > tag_off) return 0;
    r->token = buf + off;
    r->token_len = tag_off - off;
    return quic_take_bytes(buf, n, &tag_off, r->tag, QUIC_RETRY_TAG_LEN);
}

/* Parse version, both CIDs and token+tag, the byte0/length gate already
 * passed. Returns 1 ok, 0 truncated. */
static int retry_parse_after_head(const u8 *buf, usz n, quic_retry_packet *r)
{
    usz off = 5;
    r->version = ((u32)buf[1] << 24) | ((u32)buf[2] << 16) |
                 ((u32)buf[3] << 8) | (u32)buf[4];
    if (!retry_take_cids(buf, n, &off, r)) return 0;
    return take_token_tag(buf, n, off, r);
}

usz quic_retry_parse(const u8 *buf, usz n, quic_retry_packet *r)
{
    if (!retry_head_ok(buf, n)) return 0;
    return retry_parse_after_head(buf, n, r) ? n : 0;
}
