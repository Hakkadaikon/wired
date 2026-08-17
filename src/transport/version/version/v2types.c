#include "transport/version/version/v2types.h"

/* v1 logical and wire values coincide (RFC 9000 17.2). */
static const int V2_WIRE[4] = {
    1, 2, 3, 0}; /* RFC 9369 3.2, indexed by logical */

static int in_range(int v) { return v >= 0 && v < 4; }

int v1_packet_type(logical_type lt) { return in_range(lt) ? (int)lt : -1; }

int v2_packet_type(logical_type lt) { return in_range(lt) ? V2_WIRE[lt] : -1; }

logical_type v1_logical_type(int wire) {
  return in_range(wire) ? (logical_type)wire : LT_INVALID;
}

logical_type v2_logical_type(int wire) {
  for (int lt = 0; lt < 4; lt++)
    if (V2_WIRE[lt] == wire) return (logical_type)lt;
  return LT_INVALID;
}
