#include "qpack/fieldline.h"
#include "qpack/integer.h"

/* RFC 9204 4.5.2. Bit 7 marks an indexed field line; bit 6 is T (static). */
#define QPACK_INDEXED 0x80
#define QPACK_STATIC 0x40

/* The first byte's high bits: indexed pattern plus T when static. */
static u8 indexed_prefix(int is_static)
{
    return QPACK_INDEXED | (is_static ? QPACK_STATIC : 0);
}

usz quic_qpack_indexed_encode(u8 *buf, usz cap, u64 index, int is_static)
{
    return quic_qpack_int_encode(buf, cap, 6, indexed_prefix(is_static), index);
}

/* RFC 9204 4.5.2: bit 7 set marks an indexed field line. */
static int is_indexed(const u8 *buf, usz n)
{
    return n != 0 && (buf[0] & QPACK_INDEXED) != 0;
}

usz quic_qpack_indexed_decode(const u8 *buf, usz n, u64 *index, int *is_static)
{
    if (!is_indexed(buf, n)) return 0;
    *is_static = (buf[0] & QPACK_STATIC) ? 1 : 0;
    return quic_qpack_int_decode(buf, n, 6, index);
}
