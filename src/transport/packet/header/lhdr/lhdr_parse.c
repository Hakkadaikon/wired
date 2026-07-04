#include "transport/packet/header/lhdr/lhdr_parse.h"

#include "common/bytes/varint/varint.h"
#include "transport/packet/header/packet/header.h"
#include "transport/packet/header/packet/inittoken.h"

/* RFC 9000 17.2: byte 0 must have the high (header form) bit set for a long
 * header. */
static int is_long_header(quic_span pkt) {
  return pkt.n != 0 && (pkt.p[0] & 0x80) != 0;
}

/* Locate dcid/scid within pkt using the lengths parsed into h. The invariant
 * layout (RFC 9000 17.2) is byte0 | version(4) | dcid_len(1) | dcid |
 * scid_len(1) | scid. */
static void locate_cids(const u8* pkt, const wired_header* h, quic_lhdr* out) {
  out->dcid = quic_span_of(pkt + 6, h->dcid_len);
  out->scid = quic_span_of(pkt + 7 + h->dcid_len, h->scid_len);
}

/* The packet plus whether a Token field is present (Initial vs Handshake). */
typedef struct {
  quic_span pkt;
  int       is_initial;
} lhdrparse_src;

/* Read the Token field for Initial packets; Handshake has none (token empty).
 * Advances *off. Returns 1 on success, 0 on truncation. */
static int read_token(const lhdrparse_src* s, usz* off, quic_lhdr* out) {
  usz used;
  if (!s->is_initial) {
    out->token = quic_span_of((const u8*)0, 0);
    return 1;
  }
  used = quic_inittoken_get(s->pkt.p + *off, s->pkt.n - *off, &out->token);
  if (used == 0) return 0;
  *off += used;
  return 1;
}

/* Read the Length varint and record the packet-number offset after it. */
static int take_length(quic_span pkt, usz* off, quic_lhdr* out) {
  if (!quic_varint_take(quic_span_of(pkt.p, pkt.n), off, &out->length))
    return 0;
  out->pn_off = *off;
  return 1;
}

/* Validate the long form, parse byte0|version|DCID|SCID via the shared codec,
 * and resolve cid views. Returns bytes consumed, or 0 on failure. */
static usz lhdr_take_prefix(quic_span pkt, quic_lhdr* out) {
  wired_header h;
  usz          off;
  if (!is_long_header(pkt)) return 0;
  off = wired_header_parse(pkt.p, pkt.n, &h);
  if (off == 0) return 0;
  locate_cids(pkt.p, &h, out);
  return off;
}

usz quic_lhdr_pn_len(u8 byte0_unprotected) {
  return (usz)(byte0_unprotected & 0x03) + 1;
}

int quic_lhdr_parse(quic_span pkt, int is_initial, quic_lhdr* out) {
  lhdrparse_src s   = {pkt, is_initial};
  usz           off = lhdr_take_prefix(pkt, out);
  if (off == 0) return 0;
  if (!read_token(&s, &off, out)) return 0;
  return take_length(pkt, &off, out);
}
