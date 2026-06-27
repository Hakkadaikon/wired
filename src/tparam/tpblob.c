#include "tparam/tpblob.h"
#include "varint/varint.h"
#include "util/bytes.h"
#include "util/be.h"

/* --- opaque-value parameter --- */

usz quic_tparam_put_blob(u8 *buf, usz cap, u64 id, const u8 *val, usz val_len)
{
    usz off = 0;
    int ok = quic_varint_put(buf, cap, &off, id)
           & quic_varint_put(buf, cap, &off, val_len)
           & quic_put_bytes(buf, cap, &off, val, val_len);
    return ok ? off : 0;
}

/* Read both header varints; on success *len holds the value length. */
static int blob_take_hdr(const u8 *buf, usz n, usz *off, u64 *id, u64 *len)
{
    int ok = quic_varint_take(buf, n, off, id)
           & quic_varint_take(buf, n, off, len);
    return ok && *len <= n - *off;
}

usz quic_tparam_get_blob(const u8 *buf, usz n, u64 *id, const u8 **val, usz *val_len)
{
    usz off = 0;
    u64 len;
    if (!blob_take_hdr(buf, n, &off, id, &len)) return 0;
    *val = buf + off;
    *val_len = len;
    return off + (usz)len;
}

/* --- preferred_address --- */

static u16 take_be16(const u8 *p)
{
    return (u16)((u16)p[0] << 8 | p[1]);
}

/* Append a big-endian 16-bit port at *off. Returns 1 if it fit. */
static int pa_put_port(u8 *v, usz cap, usz *off, u16 port)
{
    if (*off + 2 > cap) return 0;
    quic_put_be16(v + *off, port);
    *off += 2;
    return 1;
}

/* Whole value (sans id/length) into v of cap bytes. Returns its length, 0 on
 * overflow or cid_len > 20. v is sized for the max, so writes always fit. */
static usz pa_build_value(u8 *v, usz cap, const struct quic_preferred_address *pa)
{
    usz off = 0;
    u8 cl = pa->cid_len;
    int ok = (cl <= 20)
           & quic_put_bytes(v, cap, &off, pa->ipv4, 4)
           & pa_put_port(v, cap, &off, pa->ipv4_port)
           & quic_put_bytes(v, cap, &off, pa->ipv6, 16)
           & pa_put_port(v, cap, &off, pa->ipv6_port)
           & quic_put_bytes(v, cap, &off, &cl, 1)
           & quic_put_bytes(v, cap, &off, pa->cid, cl)
           & quic_put_bytes(v, cap, &off, pa->reset_token, 16);
    return ok ? off : 0;
}

usz quic_tparam_put_preferred_address(u8 *buf, usz cap,
                                      const struct quic_preferred_address *pa)
{
    u8 v[61]; /* 4+2+16+2+1 + 20 + 16 */
    usz vlen = pa_build_value(v, sizeof(v), pa);
    if (vlen == 0) return 0;
    return quic_tparam_put_blob(buf, cap, QUIC_TP_PREFERRED_ADDRESS, v, vlen);
}

/* Read a big-endian 16-bit port at *off into *port. Returns 1 if present. */
static int pa_take_port(const u8 *v, usz len, usz *off, u16 *port)
{
    if (*off + 2 > len) return 0;
    *port = take_be16(v + *off);
    *off += 2;
    return 1;
}

/* Read fixed prefix from value view at *off. Returns 1 ok, 0 if truncated. */
static int pa_take_addrs(const u8 *v, usz len, usz *off,
                         struct quic_preferred_address *pa)
{
    return quic_take_bytes(v, len, off, pa->ipv4, 4)
         & pa_take_port(v, len, off, &pa->ipv4_port)
         & quic_take_bytes(v, len, off, pa->ipv6, 16)
         & pa_take_port(v, len, off, &pa->ipv6_port);
}

/* Read cid_len, cid, reset token. Returns 1 ok, 0 if bad. */
static int pa_take_cid_token(const u8 *v, usz len, usz *off,
                             struct quic_preferred_address *pa)
{
    int ok = quic_take_bytes(v, len, off, &pa->cid_len, 1)
           & (pa->cid_len <= 20);
    return ok & quic_take_bytes(v, len, off, pa->cid, pa->cid_len)
              & quic_take_bytes(v, len, off, pa->reset_token, 16);
}

/* Parse a value view of exactly len bytes. Returns 1 ok, 0 if malformed. */
static int pa_parse_value(const u8 *v, usz len, struct quic_preferred_address *pa)
{
    usz off = 0;
    int ok = pa_take_addrs(v, len, &off, pa)
           & pa_take_cid_token(v, len, &off, pa);
    return ok && off == len;
}

usz quic_tparam_get_preferred_address(const u8 *buf, usz n,
                                      struct quic_preferred_address *pa)
{
    u64 id;
    const u8 *v;
    usz vlen;
    usz r = quic_tparam_get_blob(buf, n, &id, &v, &vlen);
    int ok = (r != 0) & (id == QUIC_TP_PREFERRED_ADDRESS);
    if (!ok || !pa_parse_value(v, vlen, pa)) return 0;
    return r;
}
