#ifndef CRYPTO_PKI_ENCODING_X509_DIRSTRING_IMPL_H
#define CRYPTO_PKI_ENCODING_X509_DIRSTRING_IMPL_H

/* Internal to the dirstring*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/dirstring.h"

/* A cursor over one DirectoryString value that yields its RFC 4518
 * Insignificant-Space-Handling-normalized characters one at a time:
 * leading/trailing space runs yield nothing, an internal space run yields
 * exactly one space, everything else yields its case-folded octet.
 * `emitted` distinguishes a leading run (nothing produced yet, so this run
 * is insignificant even though non-space content follows) from an internal
 * run (something was already produced, so this run is significant). */
typedef struct {
  wired_span s;
  usz        i;
  int        emitted;
} dirstring_cursor;

/* One step of a parallel derseq walk: advance both cursors, comparing
 * element presence and, when both present, applying elem_eq to their
 * values. *done is set once either cursor runs out. Returns 0 to signal
 * "the two sequences differ, stop and reject". */
typedef int (*dirstring_elem_eq)(wired_span, wired_span);

#endif
