#ifndef QUIC_RSA_MGF1_H
#define QUIC_RSA_MGF1_H

#include "common/bytes/span/span.h"

/* RFC 8017 B.2.1. MGF1 mask generation with SHA-256 as the hash. Fills
 * mask from seed. */
void quic_mgf1_sha256(quic_span seed, quic_mspan mask);

#endif
