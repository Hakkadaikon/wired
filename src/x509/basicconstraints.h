#ifndef QUIC_X509_BASICCONSTRAINTS_H
#define QUIC_X509_BASICCONSTRAINTS_H

#include "sys/syscall.h"

/* RFC 5280 4.2.1.9. 1 if the basicConstraints extension is present with cA
 * TRUE; 0 if absent, cA FALSE, or malformed. */
int quic_x509_is_ca(const u8 *tbs, usz tbs_len);

#endif
