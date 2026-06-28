#include "qpackdyn/insert_encode.h"
#include "qpack/integer.h"
#include "qpack/string.h"
#include "util/bytes.h"

/* RFC 9204 4.3.3. First byte top bits 010 (H=0); the 5-bit prefix carries the
 * name length. */
#define QPACK_INSERT_LITNAME 0x40

/* RFC 9204 4.3.3. Encode the 5-bit prefixed name length then the name octets.
 * Returns bytes written, or 0 if the prefix or the name does not fit. */
static usz encode_name(u8 *out, usz cap, const u8 *name, usz name_len)
{
    usz off = quic_qpack_int_encode(out, cap, 5, QPACK_INSERT_LITNAME,
                                    name_len);
    if (off == 0) return 0;
    if (!quic_put_bytes(out, cap, &off, name, name_len)) return 0;
    return off;
}

usz quic_qdyn_insert_literal(const u8 *name, usz name_len, const u8 *value,
                             usz value_len, u8 *out, usz cap, usz *out_len)
{
    usz off = encode_name(out, cap, name, name_len);
    usz w = off ? quic_qpack_string_encode(out + off, cap - off, value,
                                           value_len)
                : 0;
    if (w == 0) return 0;
    *out_len = off + w;
    return *out_len;
}
