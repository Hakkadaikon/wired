#include "transport/packet/header/lhdr/lhdr_parse.h"
#include "transport/packet/header/packet/header.h"
#include "transport/packet/header/packet/inittoken.h"
#include "common/bytes/varint/varint.h"

/* RFC 9000 17.2: byte 0 must have the high (header form) bit set for a long
 * header. */
static int is_long_header(const u8 *pkt, usz len)
{
    return len != 0 && (pkt[0] & 0x80) != 0;
}

/* Locate dcid/scid within pkt using the lengths parsed into h. The invariant
 * layout (RFC 9000 17.2) is byte0 | version(4) | dcid_len(1) | dcid |
 * scid_len(1) | scid. */
static void locate_cids(const u8 *pkt, const quic_header *h, const u8 **dcid,
                        const u8 **scid)
{
    *dcid = pkt + 6;
    *scid = pkt + 7 + h->dcid_len;
}

/* Read the Token field for Initial packets; Handshake has none (token empty).
 * Advances *off. Returns 1 on success, 0 on truncation. */
static int read_token(const u8 *pkt, usz len, int is_initial, usz *off,
                      const u8 **token, usz *token_len)
{
    usz used;
    if (!is_initial) {
        *token = (const u8 *)0;
        *token_len = 0;
        return 1;
    }
    used = quic_inittoken_get(pkt + *off, len - *off, token, token_len);
    if (used == 0) return 0;
    *off += used;
    return 1;
}

/* Validate the long form, parse byte0|version|DCID|SCID via the shared codec,
 * and resolve cid pointers. Returns bytes consumed, or 0 on failure. */
static usz quic_lhdr_parse_prefix(const u8 *pkt, usz len, quic_header *h,
                                  const u8 **dcid, const u8 **scid)
{
    usz off;
    if (!is_long_header(pkt, len)) return 0;
    off = quic_header_parse(pkt, len, h);
    if (off == 0) return 0;
    locate_cids(pkt, h, dcid, scid);
    return off;
}

/* Read Token (Initial only) then the Length varint, advancing *off to the
 * packet number start. Returns 1 on success, 0 on truncation. */
static int read_token_and_length(const u8 *pkt, usz len, int is_initial,
                                 usz *off, const u8 **token, usz *token_len,
                                 u64 *length)
{
    if (!read_token(pkt, len, is_initial, off, token, token_len)) return 0;
    return quic_varint_take(pkt, len, off, length);
}

usz quic_lhdr_pn_len(u8 byte0_unprotected)
{
    return (usz)(byte0_unprotected & 0x03) + 1;
}

int quic_lhdr_parse(const u8 *pkt, usz len, int is_initial, const u8 **dcid,
                    u8 *dcid_len, const u8 **scid, u8 *scid_len,
                    const u8 **token, usz *token_len, u64 *length, usz *pn_off)
{
    quic_header h;
    usz off = quic_lhdr_parse_prefix(pkt, len, &h, dcid, scid);
    if (off == 0) return 0;
    *dcid_len = h.dcid_len;
    *scid_len = h.scid_len;
    if (!read_token_and_length(pkt, len, is_initial, &off, token, token_len,
                               length))
        return 0;
    *pn_off = off;
    return 1;
}
