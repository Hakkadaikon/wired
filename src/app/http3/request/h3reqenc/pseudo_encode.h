#ifndef H3REQENC_PSEUDO_ENCODE_H
#define H3REQENC_PSEUDO_ENCODE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** The request pseudo-header values (:method, :scheme, :authority, :path) to
 * encode as a field section, plus RFC 9220 3's Extended CONNECT :protocol. An
 * empty (zero-length) protocol span omits the :protocol field line, matching
 * how the other fields already indicate absence in this encoder (an empty
 * span still encodes an empty-value field line for method/scheme/authority/
 * path since they are always emitted; protocol alone is optional). */
typedef struct {
  wired_span method;
  wired_span scheme;
  wired_span authority;
  wired_span path;
  wired_span protocol;
} h3req_pseudo_in;

/* RFC 9204 4.5 / RFC 9114 4.3.1. Encode a request field section carrying the
 * four request pseudo-headers (:method, :scheme, :authority, :path): the empty
 * Encoded Field Section Prefix (Required Insert Count 0, Base 0) followed by
 * the four field lines in that order. Each pseudo-header whose (name, value)
 * pair is in the static table is emitted as an Indexed Field Line; otherwise as
 * a Literal Field Line With Name Reference against the pseudo-header's static
 * name index. When in->protocol is non-empty, a fifth field line for RFC 9220
 * 3's :protocol is appended as a Literal Field Line With Literal Name (no
 * static-table entry exists for :protocol). Returns 1 with out->len set, 0 if
 * out lacks capacity. */
int h3req_enc_pseudo(const h3req_pseudo_in* in, wired_obuf* out);

/* RFC 9114 4.4 / RFC 9110 9.3.6. Encode a CONNECT request field section: the
 * empty prefix followed by just :method=CONNECT and :authority (no :scheme or
 * :path). Returns 1 with out->len set, 0 if out lacks capacity. */
int h3req_enc_connect(wired_span authority, wired_obuf* out);

#endif
