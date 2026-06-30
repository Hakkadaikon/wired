#ifndef QUIC_H3REQENC_PSEUDO_ENCODE_H
#define QUIC_H3REQENC_PSEUDO_ENCODE_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5 / RFC 9114 4.3.1. Encode a request field section carrying the
 * four request pseudo-headers (:method, :scheme, :authority, :path): the empty
 * Encoded Field Section Prefix (Required Insert Count 0, Base 0) followed by
 * the four field lines in that order. Each pseudo-header whose (name, value)
 * pair is in the static table is emitted as an Indexed Field Line; otherwise as
 * a Literal Field Line With Name Reference against the pseudo-header's static
 * name index. Returns 1 with *out_len set, 0 if out lacks capacity. */
int quic_h3req_enc_pseudo(
    const u8 *method,
    usz       m_len,
    const u8 *path,
    usz       p_len,
    const u8 *scheme,
    usz       s_len,
    const u8 *authority,
    usz       a_len,
    u8       *out,
    usz       cap,
    usz      *out_len);

/* RFC 9114 4.4 / RFC 9110 9.3.6. Encode a CONNECT request field section: the
 * empty prefix followed by just :method=CONNECT and :authority (no :scheme or
 * :path). Returns 1 with *out_len set, 0 if out lacks capacity. */
int quic_h3req_enc_connect(
    const u8 *authority, usz a_len, u8 *out, usz cap, usz *out_len);

#endif
