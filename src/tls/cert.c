#include "tls/cert.h"

/* TLS uses fixed big-endian length prefixes. A small cursor reads them and
 * bounds every access against the message end. */
typedef struct { const u8 *b; usz n; usz off; } cur;

/* Read a k-byte (1..3) big-endian length into *v. Returns 1 if it fits. */
static int take_len(cur *c, usz k, u32 *v)
{
    if (c->off + k > c->n) return 0;
    *v = 0;
    for (usz i = 0; i < k; i++) *v = (*v << 8) | c->b[c->off + i];
    c->off += k;
    return 1;
}

/* Take a view of len bytes at the cursor. Returns 1 if it fits. */
static int take_view(cur *c, u32 len, const u8 **out)
{
    if (c->off + len > c->n) return 0;
    *out = c->b + c->off;
    c->off += len;
    return 1;
}

/* Read a k-byte length then that many bytes as a view. */
static int take_vec(cur *c, usz k, const u8 **out, u32 *len)
{
    if (!take_len(c, k, len)) return 0;
    return take_view(c, *len, out);
}

/* The end-entity entry: cert_data (3-byte length) then its extensions
 * (2-byte length), within the certificate_list. */
static int take_entry(cur *c, quic_tls_cert_entry *first)
{
    const u8 *ext;
    u32 elen;
    if (!take_vec(c, 3, &first->cert_data, &first->cert_len)) return 0;
    return take_vec(c, 2, &ext, &elen); /* skip this entry's extensions */
}

int quic_tls_cert_parse(const u8 *buf, usz n,
                        const u8 **context, u32 *context_len,
                        quic_tls_cert_entry *first)
{
    cur c = {buf, n, 0};
    const u8 *list;
    u32 list_len;
    cur lc;
    if (!take_vec(&c, 1, context, context_len)) return 0;
    if (!take_vec(&c, 3, &list, &list_len)) return 0;
    lc = (cur){list, list_len, 0};
    return take_entry(&lc, first); /* first entry is the end-entity cert */
}

int quic_tls_certverify_parse(const u8 *buf, usz n, u16 *scheme,
                              const u8 **sig, u16 *sig_len)
{
    cur c = {buf, n, 0};
    u32 s, slen;
    const u8 *sv;
    if (!take_len(&c, 2, &s)) return 0;
    if (!take_vec(&c, 2, &sv, &slen)) return 0;
    *scheme = (u16)s;
    *sig = sv;
    *sig_len = (u16)slen;
    return 1;
}
