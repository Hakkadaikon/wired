#include "app/qpack/qpack/fieldline.h"

#include "app/qpack/qpack/integer.h"

/* RFC 9204 4.5.2. Bit 7 marks an indexed field line; bit 6 is T (static). */
#define QPACK_INDEXED 0x80
#define QPACK_STATIC 0x40

/* The first byte's high bits: indexed pattern plus T when static. */
static u8 indexed_prefix(int is_static) {
  return QPACK_INDEXED | (is_static ? QPACK_STATIC : 0);
}

usz quic_qpack_indexed_encode(quic_mspan buf, u64 index, int is_static) {
  quic_qpack_pfx pfx = {6, indexed_prefix(is_static)};
  return quic_qpack_int_encode(buf, pfx, index);
}

/* RFC 9204 4.5.2: bit 7 set marks an indexed field line. */
static int is_indexed(quic_span buf) {
  return buf.n != 0 && (buf.p[0] & QPACK_INDEXED) != 0;
}

usz quic_qpack_indexed_decode(quic_span buf, u64 *index, int *is_static) {
  if (!is_indexed(buf)) return 0;
  *is_static = (buf.p[0] & QPACK_STATIC) ? 1 : 0;
  return quic_qpack_int_decode(buf, 6, index);
}
