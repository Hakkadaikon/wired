#ifndef TESTS_NCID_KEY_H
#define TESTS_NCID_KEY_H

#include "transport/packet/frame/frame/ncid_worker.h"

/* One fixed CID routing key (RFC 9312 2.6, ncid_route_encode) for the tests
 * that build routed CIDs: k[0] xor key, k[1] and k[2] odd multipliers. */
static const ncid_route_key test_ncid_key = {
    {0x0123456789abcdefULL, 0x9e3779b97f4a7c15ULL, 0xbf58476d1ce4e5b9ULL}};

#endif
