/* libFuzzer harness for post-handshake connection I/O: with keys already
 * installed at every protection level (RFC 9001 4/5), split the fuzzer input
 * into its coalesced packets (RFC 9000 12.2) and feed each one through
 * quic_connio_recv -- open, dispatch every recovered frame (STREAM, ACK,
 * MAX_DATA, STOP_SENDING, RESET_STREAM, ...). Mirrors cloudflare/quiche's
 * packets_posths_server target: fuzz the steady-state receive path without
 * paying for a real handshake. Hosted build only -- mirrors tests/run.c's
 * unity-include style, but this file itself may use the standard library
 * since it lives outside src/. */
#include <stddef.h>
#include <stdint.h>

#include "app/datagram/datagram/datagram.c"
#include "app/datagram/dgdeliver/dg_recv.c"
#include "common/bytes/varint/varint.c"
#include "crypto/kdf/keys/keyset.c"
#include "crypto/kdf/keys/promote.c"
#include "crypto/symmetric/aead/aes/aes.c"
#include "crypto/symmetric/aead/chacha/aead.c"
#include "crypto/symmetric/aead/chacha/chacha20.c"
#include "crypto/symmetric/aead/chacha/poly1305.c"
#include "crypto/symmetric/aead/gcm/gcm.c"
#include "crypto/symmetric/aead/gcmx86/gcmx86.c"
#include "crypto/symmetric/hash/hash/hmac.c"
#include "crypto/symmetric/hash/hash/sha256.c"
#include "crypto/symmetric/hash/hash/sha384.c"
#include "crypto/symmetric/hash/hash/sha512.c"
#include "crypto/kdf/hkdf/hkdf.c"
#include "tls/handshake/core/tls/aead_params.c"
#include "tls/handshake/core/tls/cipher.c"
#include "tls/keys/keyupdate/aeadintegrity.c"
#include "transport/conn/cid/path/antiamp.c"
#include "transport/conn/lifecycle/conn/pnspace.c"
#include "transport/conn/pnspace/crypto_stream/crypto_rx.c"
#include "transport/conn/loop/connio/connio.c"
#include "transport/conn/loop/connloop/connloop.c"
#include "transport/conn/loop/connrunner/level.c"
#include "transport/conn/pnspace/pnspaces/spaces.c"
#include "transport/io/udp/udploop/antiamp_gate.c"
#include "transport/packet/frame/frame/ack.c"
#include "transport/packet/frame/frame/ack_range.c"
#include "transport/packet/frame/frame/connctl.c"
#include "transport/packet/frame/frame/dispatch.c"
#include "transport/packet/frame/frame/flowctl.c"
#include "transport/packet/frame/frame/frame.c"
#include "transport/packet/frame/frame/ncid.c"
#include "transport/packet/frame/frame/permit.c"
#include "transport/packet/frame/frame/stream_bounds.c"
#include "transport/packet/frame/frame/stream_ctl.c"
#include "transport/packet/frame/framedispatch/dispatch_state.c"
#include "transport/packet/frame/pipeline/framewalk.c"
#include "transport/packet/frame/pipeline/rxpacket.c"
#include "transport/packet/frame/pipeline/txpacket.c"
#include "transport/packet/header/packet/coalesce.c"
#include "transport/packet/header/packet/header.c"
#include "transport/packet/header/packet/inittoken.c"
#include "transport/packet/header/packet/pnlen.c"
#include "transport/packet/header/packet/pnum.c"
#include "transport/packet/header/packet/ptype.c"
#include "transport/packet/header/lhdr/lhdr_build.c"
#include "transport/packet/header/lhdr/lhdr_parse.c"
#include "transport/packet/build/vpn/vpn_open.c"
#include "transport/packet/protect/hp/hp.c"
#include "transport/packet/protect/hp/hp_chacha.c"
#include "transport/packet/protect/hp/hpapply.c"
#include "transport/packet/protect/hp/hpsample.c"
#include "transport/packet/protect/protect/protect.c"
#include "transport/packet/protect/protect_suite/aead_suite.c"
#include "transport/packet/protect/protect_suite/hp_suite.c"
#include "transport/recovery/rtx/sentpkt/ack_process.c"
#include "transport/recovery/rtx/sentpkt/sentpkt.c"
#include "transport/stream/flow/flow/credit.c"
#include "transport/stream/flow/flow/reassemble.c"
#include "transport/stream/flow/flow/stream_read.c"
#include "transport/version/version/v2types.c"
#include "transport/version/version/version.c"

/* Install a dummy key at every protection level and fast-forward the gating
 * state to look like a connection that just finished its handshake: send
 * level at Handshake (so the next promotion may reach 1-RTT), handshake
 * marked complete, address validated. No real TLS runs -- quic_connio_recv's
 * AEAD open/frame-dispatch path runs the same whether the key material is
 * real or zeroed, and connio_test.c's arm_onertt proves that. */
static void arm_onertt(quic_connio *io, int is_server) {
  quic_connio_init_in in = {is_server, 0x43, 1u << 20};
  quic_connio_init(io, wired_span_of((const u8 *)"\x01\x02\x03\x04", 4), &in);

  quic_initial_keys k = {0};
  quic_keyset_install(&io->loop.keys, QUIC_LEVEL_INITIAL, &k);
  quic_keyset_install(&io->loop.keys, QUIC_LEVEL_HANDSHAKE, &k);
  quic_keyset_install(&io->loop.keys, QUIC_LEVEL_ONERTT, &k);
  io->loop.validated          = 1;
  io->loop.send_level         = QUIC_LEVEL_HANDSHAKE;
  io->loop.handshake_complete = 1;
}

/* quic_connio_recv opens its datagram in place (header protection removal,
 * then AEAD), but libFuzzer's input buffer is `const` and must never be
 * mutated -- so each coalesced packet is copied into a scratch buffer first,
 * same as a real UDP receive would hand connio_recv its own read buffer
 * rather than the kernel's. A packet longer than the scratch buffer is
 * skipped: no valid QUIC packet is anywhere near that size. */
#define SCRATCH_CAP 4096

/* Feed one coalesced packet through connio_recv at the level its own first
 * byte selects (RFC 9000 17.2/17.3), same mapping the real receive loop
 * uses. A packet whose first byte maps to no loop-handled level (0-RTT,
 * Retry) is simply skipped -- there is nothing post-handshake to fuzz there. */
static void feed_one(quic_connio *io, const u8 *data, usz len) {
  static u8 scratch[SCRATCH_CAP];
  int       level;
  if (len == 0 || len > SCRATCH_CAP) return;
  if (!quic_connrunner_packet_level(data[0], &level)) return;
  for (usz i = 0; i < len; i++) scratch[i] = data[i];
  quic_connio_recv(io, level, wired_mspan_of(scratch, len));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const u8 *buf = (const u8 *)data;
  usz       n   = (usz)size;

  quic_connio io;
  arm_onertt(&io, 1); /* server: the quiche posths_server target's shape */

  /* RFC 9000 12.2: walk every coalesced packet in the datagram and feed each
   * one through the post-handshake receive path in turn. quic_coalesce_next
   * consumes the cursor's offset on every yield (or stops), so this loop is
   * bounded by the input length -- no manual iteration cap needed, same as
   * fuzz_header.c. */
  quic_coalesce_iter it;
  quic_coalesce_begin(&it, buf, n);
  quic_coalesced pkt;
  while (quic_coalesce_next(&it, &pkt)) {
    feed_one(&io, pkt.data, pkt.len);
  }

  return 0;
}
