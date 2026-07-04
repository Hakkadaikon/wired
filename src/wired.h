#ifndef WIRED_H
#define WIRED_H

/** @file
 * Single-header public entry for the wired QUIC/HTTP3 SDK. Include this and
 * (optionally, in exactly one translation unit) define WIRED_MAIN before it to
 * also get the libc-named memcpy/memset a freestanding binary needs. See
 * examples/word_list for a complete server. */

#include "app/http3/server/certreload/certreload.h"
#include "app/http3/server/mimetype/mimetype.h"
#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "app/http3/server/srvrun/srvrun.h"
#include "app/http3/server/staticfile/staticfile.h"
#include "common/bytes/util/bytes.h"
#include "common/platform/cliargs/cliargs.h"
#include "common/platform/debug/debug.h"
#include "common/platform/fio/fio.h"
#include "crypto/pki/encoding/eckey/eckey.h"
#include "crypto/pki/encoding/pem/pem.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/server/server.h"
#include "transport/io/socket/io/udp.h"
#include "transport/packet/header/packet/header.h"

/* A binary that supplies its own _start (-nostdlib) must also define the
 * libc-named memcpy/memset the compiler emits for struct/array copies. Define
 * WIRED_MAIN in the single application translation unit to emit them here,
 * forwarding to the SDK's quic_memcpy/quic_memset. */
#ifdef WIRED_MAIN
void *memcpy(void *dst, const void *src, usz n) {
  return quic_memcpy(dst, src, n);
}
void *memset(void *dst, int c, usz n) { return quic_memset(dst, c, n); }
#endif

#endif
