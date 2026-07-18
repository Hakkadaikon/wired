#ifndef WIRED_H
#define WIRED_H

/** @file
 * Single-header public entry for the wired QUIC/HTTP3 SDK. Include this and
 * (optionally, in exactly one translation unit) define WIRED_MAIN before it to
 * also get the libc-named memcpy/memset and the freestanding `_start` entry
 * point a -nostdlib binary needs. The application TU that defines WIRED_MAIN
 * must also define `int wired_main(int argc, char** argv)` as its own main.
 * See examples/word_list for a complete server. */

#include "app/http3/server/certreload/certreload.h"
#include "app/http3/server/mimetype/mimetype.h"
#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvdriver/srvdriver.h"
#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "app/http3/server/srvrun/srvrun.h"
#include "app/http3/server/staticfile/staticfile.h"
#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"
#include "app/webtransport/errmap/errmap/errmap.h"
#include "app/webtransport/wtwire/wtwire.h"
#include "common/bytes/util/bytes.h"
#include "common/platform/cliargs/cliargs.h"
#include "common/platform/clock/clock.h"
#include "common/platform/debug/debug.h"
#include "common/platform/envp/envp.h"
#include "common/platform/exit/exit.h"
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
void* memcpy(void* dst, const void* src, usz n) {
  return quic_memcpy(dst, src, n);
}
void* memset(void* dst, int c, usz n) { return quic_memset(dst, c, n); }

/* Freestanding entry point (x86_64-linux, -nostdlib). Each application TU
 * that defines WIRED_MAIN must also define `int wired_main(int argc, char**
 * argv)` (non-static, so this can link to it) as its own main. Linux enters
 * _start with RSP%16==0 and no return address on the stack; the asm below
 * recovers argc/argv from the kernel-built initial stack, 16-byte-aligns
 * RSP for the SysV ABI's post-call state wired_main expects (its own
 * force_align_arg_pointer attribute handles the rest), and exits with
 * wired_main's return value. */
int wired_main(int argc, char** argv);

__attribute__((naked)) void _start(void) {
  asm volatile(
      "mov (%rsp), %rdi\n"
      "lea 8(%rsp), %rsi\n"
      "and $-16, %rsp\n"
      "call wired_main\n"
      "mov %eax, %edi\n"
      "mov $60, %eax\n" /* SYS_exit */
      "syscall\n");
}
#endif

#endif
