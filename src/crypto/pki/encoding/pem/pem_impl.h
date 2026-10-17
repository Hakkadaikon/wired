#ifndef CRYPTO_PKI_ENCODING_PEM_PEM_IMPL_H
#define CRYPTO_PKI_ENCODING_PEM_PEM_IMPL_H

/* Internal to the pem*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/pki/encoding/pem/pem.h"

/* RFC 4648 4 reverse alphabet, evaluated arithmetically: 0-63 = sextet
 * value, 64 = pad '=', 65 = skip (CR/LF), 66 = invalid. A 256-entry lookup
 * table indexed by the input byte would make the cache line touched depend
 * on the decoded sextet, which for a PRIVATE KEY block (certreload decodes
 * the server's key through this path) leaks key bits to a co-resident
 * observer (CVE-2021-24116 class). Each input byte is instead run through
 * every range below, in a fixed order, with a branch-free in-range mask. */
typedef struct {
  u8 lo, hi, base;
} pem_b64_range;

#define PEM_B64_RANGE_COUNT (sizeof(pem_b64_ranges) / sizeof(pem_b64_ranges[0]))
#define PEM_B64_INVALID 66

u8  pem_b64_code(u8 c);
int pem_find(wired_span text, usz from, wired_span nd, usz* pos);
usz pem_line_end(wired_span text, usz i);
int pem_head(wired_span text, usz at, wired_span* label, usz* body);

extern const u8 pem_end_tag[10];
extern const u8 pem_quad_n[4];

#endif
