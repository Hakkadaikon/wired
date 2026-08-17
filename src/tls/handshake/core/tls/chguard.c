#include "tls/handshake/core/tls/chguard.h"

/* RFC 8446 4.2: track extension_types seen so far in one ClientHello. */
#define CHGUARD_MAX_SEEN 32

typedef struct {
  unsigned seen[CHGUARD_MAX_SEEN];
  usz      count;
} chguard_seen;

/* True if type is already present in s->seen[0..count). */
static int chguard_type_seen(const chguard_seen* s, unsigned type) {
  for (usz i = 0; i < s->count; i++)
    if (s->seen[i] == type) return 1;
  return 0;
}

/* True if type is new and there is room to record it. */
static int chguard_can_record(const chguard_seen* s, unsigned type) {
  return s->count < CHGUARD_MAX_SEEN && !chguard_type_seen(s, type);
}

/* One extension TLV's decoded type and total (header+data) length. */
typedef struct {
  unsigned type;
  usz      total;
} chguard_tlv;

/* Read the type(2)+len(2) header at exts.p+off. Returns 1 and fills tlv, or 0
 * if the header or its declared data overruns exts. */
static int read_tlv(wired_span exts, usz off, chguard_tlv* tlv) {
  usz dlen;
  if (off + 4 > exts.n) return 0;
  tlv->type  = (unsigned)exts.p[off] << 8 | exts.p[off + 1];
  dlen       = (usz)exts.p[off + 2] << 8 | exts.p[off + 3];
  tlv->total = 4 + dlen;
  return off + tlv->total <= exts.n;
}

/* Read one type(2)+len(2)+data TLV at exts.p+off. Returns bytes consumed,
 * or 0 on a malformed TLV, a full table, or a duplicate type. */
static usz chguard_seen_step(chguard_seen* s, wired_span exts, usz off) {
  chguard_tlv tlv;
  if (!read_tlv(exts, off, &tlv) || !chguard_can_record(s, tlv.type)) return 0;
  s->seen[s->count++] = tlv.type;
  return tlv.total;
}

int chguard_no_dup_ext(wired_span exts) {
  chguard_seen s   = {.count = 0};
  usz          off = 0;
  while (off < exts.n) {
    usz r = chguard_seen_step(&s, exts, off);
    if (r == 0) return 0;
    off += r;
  }
  return 1;
}

int chguard_psk_modes_ok(int has_psk, int modes_dhe_ke) {
  return !has_psk || modes_dhe_ke;
}

int chguard_psk_last(wired_span exts, wired_span psk) {
  if (psk.n == 0) return 1;
  return psk.p + psk.n == exts.p + exts.n;
}

int chguard_require_algs(int found_sig_algs, int found_groups) {
  return found_sig_algs && found_groups;
}

/* RFC 8446 4.2's registry, restricted to the extension_type code points this
 * SDK recognizes elsewhere (grep 'QUIC_EXT_\|QUIC_TLSEXT_T_\|SNI_TYPE\|
 * ALPN_TYPE' across src/tls): every one of these IS specified for
 * ClientHello, so none is CH-illegal. oid_filters (48) is the one RFC 8446
 * extension_type specified ONLY for CertificateRequest, never ClientHello --
 * the sole code point this table treats as a violation if seen in a CH. */
#define CHGUARD_OID_FILTERS 48

static int ch_legal_ext_type(unsigned type) {
  return type != CHGUARD_OID_FILTERS;
}

/* One TLV's extension_type is CH-legal (see ch_legal_ext_type above). */
static int ch_legal_step(wired_span exts, usz off, usz* consumed) {
  chguard_tlv tlv;
  if (!read_tlv(exts, off, &tlv)) return 0;
  *consumed = tlv.total;
  return ch_legal_ext_type(tlv.type);
}

int chguard_ch_legal_exts(wired_span exts) {
  usz off = 0;
  while (off < exts.n) {
    usz consumed = 0;
    if (!ch_legal_step(exts, off, &consumed)) return 0;
    off += consumed;
  }
  return 1;
}
