#ifndef QUIC_X509_BASICCONSTRAINTS_H
#define QUIC_X509_BASICCONSTRAINTS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.9. 1 if the basicConstraints extension is present with cA
 * TRUE; 0 if absent, cA FALSE, or malformed. */
int quic_x509_is_ca(quic_span tbs);

/* RFC 5280 6.1.4 (m). 1 if the cert's pathLenConstraint permits `depth`
 * intermediate certificates below it (the leaf is not counted). An absent
 * constraint is unconstrained; a present but malformed or negative INTEGER
 * rejects. Meaningful only on a cert that passed quic_x509_is_ca. */
int quic_x509_pathlen_allows(quic_span tbs, usz depth);

#endif
