#include "transport/packet/header/packet/header.h"

/* Copy len bytes src->dst unconditionally (len already validated). */
static void copy_cid(u8 *dst, const u8 *src, u8 len)
{
    for (u8 i = 0; i < len; i++) dst[i] = src[i];
}

/* True if a CID of length len starting at off fits in n bytes and is
 * within the QUIC max CID length. */
static int cid_fits(u8 len, usz off, usz n)
{
    return len <= QUIC_MAX_CID_LEN && off + 1 + (usz)len <= n;
}

/* Read one length-prefixed CID at buf (n readable). On success advances
 * off by 1+len and fills dst and dst_len. Returns 1 ok, 0 truncated. */
static int read_cid(const u8 *buf, usz n, usz *off, u8 *dst, u8 *dst_len)
{
    u8 len;
    if (*off >= n) return 0;
    len = buf[*off];
    if (!cid_fits(len, *off, n)) return 0;
    *dst_len = len;
    copy_cid(dst, buf + *off + 1, len);
    *off += 1 + (usz)len;
    return 1;
}

static usz parse_long(const u8 *buf, usz n, quic_header *h)
{
    usz off = 5; /* byte0 + 4-byte version */
    h->form = QUIC_FORM_LONG;
    h->long_type = (buf[0] >> 4) & 0x3;
    h->version = ((u32)buf[1] << 24) | ((u32)buf[2] << 16) |
                 ((u32)buf[3] << 8) | (u32)buf[4];
    if (!read_cid(buf, n, &off, h->dcid, &h->dcid_len)) return 0;
    if (!read_cid(buf, n, &off, h->scid, &h->scid_len)) return 0;
    return off;
}

/* Short header: byte0 then DCID of the connection's known local length. */
static usz parse_short(const u8 *buf, usz n, quic_header *h, u8 dcid_len)
{
    if (!cid_fits(dcid_len, 0, n)) return 0;
    h->form = QUIC_FORM_SHORT;
    copy_cid(h->dcid, buf + 1, dcid_len);
    h->dcid_len = dcid_len;
    h->scid_len = 0;
    return 1 + (usz)dcid_len;
}

usz quic_header_parse(const u8 *buf, usz n, quic_header *h)
{
    if (n == 0) return 0;
    if (buf[0] & 0x80) return parse_long(buf, n, h);
    return parse_short(buf, n, h, h->dcid_len); /* caller presets dcid_len */
}

/* Append a length-prefixed CID; advance *off. Returns 1 ok, 0 if no room. */
static int write_cid(u8 *buf, usz cap, usz *off, const u8 *cid, u8 len)
{
    if (*off + 1 + (usz)len > cap) return 0;
    buf[*off] = len;
    for (u8 i = 0; i < len; i++) buf[*off + 1 + i] = cid[i];
    *off += 1 + (usz)len;
    return 1;
}

/* Write byte0 (long form + fixed bit + type) and the 4-byte version into
 * buf (cap bytes). Returns 5 (bytes written) or 0 if it does not fit. */
static usz put_long_prefix(u8 *buf, usz cap, const quic_header *h)
{
    if (cap < 5) return 0;
    buf[0] = 0xC0 | (u8)(h->long_type << 4);
    buf[1] = (u8)(h->version >> 24);
    buf[2] = (u8)(h->version >> 16);
    buf[3] = (u8)(h->version >> 8);
    buf[4] = (u8)h->version;
    return 5;
}

/* Append both CIDs (dcid then scid) starting at *off; zero *off on overflow. */
static void write_cids(u8 *buf, usz cap, usz *off, const quic_header *h)
{
    const u8 *cid[2] = {h->dcid, h->scid};
    const u8 cid_len[2] = {h->dcid_len, h->scid_len};
    for (usz i = 0; i < 2; i++)
        if (!write_cid(buf, cap, off, cid[i], cid_len[i])) *off = 0;
}

usz quic_header_build_long(u8 *buf, usz cap, const quic_header *h)
{
    usz off = put_long_prefix(buf, cap, h);
    if (off != 0) write_cids(buf, cap, &off, h);
    return off;
}
