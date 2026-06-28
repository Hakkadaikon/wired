#include "qpackdyn/field_decode.h"
#include "qpackdyn/cstr.h"
#include "qpack/fieldline.h"
#include "qpack/dynget.h"
#include "qpack/relindex.h"
#include "qpack/static_table.h"

/* RFC 9204 4.5.2. Resolve a static-table index into borrowed name/value with
 * their measured lengths. Returns 1 ok, 0 if the index is out of range. */
static int resolve_static(u64 index, const u8 **name, usz *name_len,
                          const u8 **value, usz *value_len)
{
    const char *n, *v;
    if (!quic_qpack_static_get((usz)index, &n, &v)) return 0;
    *name = (const u8 *)n;
    *value = (const u8 *)v;
    *name_len = quic_qdyn_cstr_len(n);
    *value_len = quic_qdyn_cstr_len(v);
    return 1;
}

/* RFC 9204 4.5.2 / 3.2.5. Resolve a dynamic relative index against base into a
 * borrowed live entry. Returns 1 ok, 0 if no live entry resolves. */
static int resolve_dynamic(const quic_qpack_dyn *table, u64 base, u64 rel,
                           const u8 **name, usz *name_len, const u8 **value,
                           usz *value_len)
{
    u64 abs = quic_qpack_rel_to_abs(base, rel);
    return quic_qpack_dyn_get(table, abs, name, name_len, value, value_len);
}

int quic_qdyn_decode_field(const quic_qpack_dyn *table, u64 base, const u8 *fs,
                           usz fs_len, usz pos, const u8 **name, usz *name_len,
                           const u8 **value, usz *value_len, usz *consumed)
{
    u64 index;
    int is_static;
    usz used = quic_qpack_indexed_decode(fs + pos, fs_len - pos, &index,
                                         &is_static);
    if (used == 0) return 0;
    *consumed = used;
    if (is_static)
        return resolve_static(index, name, name_len, value, value_len);
    return resolve_dynamic(table, base, index, name, name_len, value,
                           value_len);
}
