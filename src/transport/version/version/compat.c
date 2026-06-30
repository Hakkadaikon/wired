#include "transport/version/version/compat.h"

/* RFC 9368 2.1: a version is compatible with itself. */
static int is_known(u32 v) {
  return v == QUIC_VERSION_1 || v == QUIC_VERSION_2;
}

int quic_version_compatible(u32 a, u32 b) {
  if (a == b) return is_known(a);    /* unknown versions: no known mapping */
  return is_known(a) && is_known(b); /* v1 <-> v2 (RFC 9369 3.1) */
}
