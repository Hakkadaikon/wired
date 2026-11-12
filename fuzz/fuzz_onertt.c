/* libFuzzer harness for the server's packet-open path: split the fuzzer
 * input into its coalesced packets (RFC 9000 12.2) and open each one through
 * wired_srvloop_recv, the call the server's per-datagram step makes
 * (srvloop_step_one) -- Initial under the keys derived from the original
 * DCID (RFC 9001 5.2), Handshake under the client handshake key, 1-RTT
 * through header protection, the Key Phase bit and key-generation choice
 * (RFC 9001 5.4 / 6.3-6.5), with the version checks of RFC 9369 4.1 in
 * front. The 1-RTT keys are all-zero, as if the handshake had just
 * finished, so the open runs without paying for a real handshake. Hosted
 * build only -- mirrors tests/run.c's unity-include style, but this file
 * itself may use the standard library since it lives outside src/. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "app/datagram/datagram/datagram.c"
#include "app/datagram/datagram/zerortt_dgram.c"
#include "app/http3/core/h3/frame.c"
#include "app/http3/core/h3/frame_put.c"
#include "app/http3/core/h3/grease.c"
#include "app/http3/core/h3settings/control_open.c"
#include "app/http3/core/h3settings/control_settings.c"
#include "app/http3/core/h3settings/settings_build.c"
#include "app/http3/server/srvloop/keys.c"
#include "app/http3/server/srvloop/recv.c"
#include "app/http3/server/srvloop/recv_onertt.c"
#include "app/http3/server/srvloop/recv_version.c"
#include "common/bytes/varint/varint.c"
#include "common/diag/error/error.c"
#include "common/platform/clock/clock.c"
#include "common/platform/rng/rng.c"
#include "crypto/asymmetric/ecc/ecdsasig/der_int.c"
#include "crypto/asymmetric/ecc/ecdsasig/sig_value.c"
#include "crypto/asymmetric/ecc/p256/p256_ecdhe.c"
#include "crypto/asymmetric/ecc/p256/p256_field.c"
#include "crypto/asymmetric/ecc/p256/p256_field_fe.c"
#include "crypto/asymmetric/ecc/p256/p256_field_fp.c"
#include "crypto/asymmetric/ecc/p256/p256_field_mont.c"
#include "crypto/asymmetric/ecc/p256/p256_field_p256.c"
#include "crypto/asymmetric/ecc/p256/p256_field_p256_fp.c"
#include "crypto/asymmetric/ecc/p256/p256_point.c"
#include "crypto/asymmetric/ecc/p256/p256_point_ec.c"
#include "crypto/asymmetric/ecc/p256/p256_point_fp.c"
#include "crypto/asymmetric/ecc/p256/p256_point_jac.c"
#include "crypto/asymmetric/ecc/p256fixed/p256fixed.c"
#include "crypto/asymmetric/ecc/p256fixed/p256fixed_table.c"
#include "crypto/asymmetric/ecc/p256sign/rfc6979.c"
#include "crypto/asymmetric/ecc/p256sign/sign.c"
#include "crypto/kdf/hkdf/hkdf.c"
#include "crypto/kdf/hkdf/hkdf_expand.c"
#include "crypto/kdf/keys/keyset.c"
#include "crypto/pki/cert/p256cert/p256cert.c"
#include "crypto/pki/cert/p256cert/spki.c"
#include "crypto/pki/cert/p256cert/tbs.c"
#include "crypto/pki/cert/selfcert/derenc.c"
#include "crypto/pki/encoding/asn1/der.c"
#include "crypto/pki/encoding/asn1/derseq.c"
#include "crypto/pki/encoding/asn1/derval.c"
#include "crypto/pki/encoding/x509/san.c"
#include "crypto/pki/encoding/x509/san_ipv4.c"
#include "crypto/pki/encoding/x509/san_x509.c"
#include "crypto/pki/encoding/x509/sigalgoid.c"
#include "crypto/pki/encoding/x509/validity.c"
#include "crypto/pki/encoding/x509/x509.c"
#include "crypto/pki/encoding/x509/x509_ext.c"
#include "crypto/symmetric/aead/aes/aes.c"
#include "crypto/symmetric/aead/aes/aes_shift.c"
#include "crypto/symmetric/aead/chacha/aead.c"
#include "crypto/symmetric/aead/chacha/chacha20.c"
#include "crypto/symmetric/aead/chacha/poly1305.c"
#include "crypto/symmetric/aead/chacha/poly1305_full.c"
#include "crypto/symmetric/aead/gcm/gcm_ctr.c"
#include "crypto/symmetric/aead/gcm/gcm_gcm256.c"
#include "crypto/symmetric/aead/gcm/gcm_open.c"
#include "crypto/symmetric/aead/gcmx86/gcmx86.c"
#include "crypto/symmetric/aead/gcmx86/gcmx86_ctr.c"
#include "crypto/symmetric/aead/gcmx86/gcmx86_load.c"
#include "crypto/symmetric/aead/gcmx86/gcmx86_seal.c"
#include "crypto/symmetric/hash/hash/hmac.c"
#include "crypto/symmetric/hash/hash/sha256.c"
#include "crypto/symmetric/hash/hash/sha384.c"
#include "crypto/symmetric/hash/hash/sha512.c"
#include "crypto/symmetric/hash/hash/sha512_put.c"
#include "tls/ext/grease/bitset.c"
#include "tls/ext/grease/grease.c"
#include "tls/ext/legacy/legacy_fields.c"
#include "tls/ext/salpn/ch_ext.c"
#include "tls/ext/salpn/negotiate.c"
#include "tls/ext/salpn/salpn_raw.c"
#include "tls/ext/salpn/salpn_raw_server.c"
#include "tls/ext/salpn/sni_check.c"
#include "tls/ext/salpn/sni_extract.c"
#include "tls/ext/stp/parse_tp.c"
#include "tls/ext/stp/server_tp.c"
#include "tls/ext/tlsext/preshared.c"
#include "tls/ext/tlsext/pskmodes.c"
#include "tls/ext/tparam/tparam.c"
#include "tls/ext/tparam/tpblob.c"
#include "tls/ext/tparam/tpcheck.c"
#include "tls/handshake/core/hrr/hrr_build.c"
#include "tls/handshake/core/sdrv/sdrv.c"
#include "tls/handshake/core/sdrv/sdrv_certsig.c"
#include "tls/handshake/core/sdrv/sdrv_ch.c"
#include "tls/handshake/core/sdrv/sdrv_ch_decode.c"
#include "tls/handshake/core/sdrv/sdrv_ch_psk.c"
#include "tls/handshake/core/sdrv/sdrv_ch_require.c"
#include "tls/handshake/core/sdrv/sdrv_ch_shape.c"
#include "tls/handshake/core/sdrv/sdrv_ch_tp.c"
#include "tls/handshake/core/sdrv/sdrv_early.c"
#include "tls/handshake/core/sdrv/sdrv_early_ticket.c"
#include "tls/handshake/core/sdrv/sdrv_hrr.c"
#include "tls/handshake/core/sdrv/sdrv_p256.c"
#include "tls/handshake/core/sdrv/sdrv_psk.c"
#include "tls/handshake/core/sdrv/sdrv_set.c"
#include "tls/handshake/core/sdrv/sdrv_take.c"
#include "tls/handshake/core/tls/aead_params.c"
#include "tls/handshake/core/tls/alpn_match.c"
#include "tls/handshake/core/tls/appkeys.c"
#include "tls/handshake/core/tls/binder.c"
#include "tls/handshake/core/tls/chguard.c"
#include "tls/handshake/core/tls/cipher.c"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/encext_check.c"
#include "tls/handshake/core/tls/exporter.c"
#include "tls/handshake/core/tls/ext_algs.c"
#include "tls/handshake/core/tls/ext_block.c"
#include "tls/handshake/core/tls/ext_keyshare.c"
#include "tls/handshake/core/tls/ext_versions.c"
#include "tls/handshake/core/tls/finished.c"
#include "tls/handshake/core/tls/handshake.c"
#include "tls/handshake/core/tls/hp_select.c"
#include "tls/handshake/core/tls/initial.c"
#include "tls/handshake/core/tls/master.c"
#include "tls/handshake/core/tls/schedule.c"
#include "tls/handshake/core/tls/sni.c"
#include "tls/handshake/core/tls/suitehash.c"
#include "tls/handshake/core/tls/ticketfreshness.c"
#include "tls/handshake/core/tls/ticketversion.c"
#include "tls/handshake/core/tls/tpext.c"
#include "tls/handshake/core/tls/transcript.c"
#include "tls/handshake/core/tls/zerortt_params.c"
#include "tls/handshake/roles/server/server.c"
#include "tls/handshake/roles/srvfin/complete.c"
#include "tls/keys/keyupdate/keyphase.c"
#include "tls/keys/keyupdate/kuderive.c"
#include "tls/keys/keyupdate/pncheck.c"
#include "tls/keys/kuswitch/derive.c"
#include "tls/keys/kuswitch/twogen.c"
#include "tls/keys/schedule_drive/keyschedule.c"
#include "tls/keys/ticket/ticket.c"
#include "transport/conn/cid/spin/spin.c"
#include "transport/conn/lifecycle/idledrive/idlenego.c"
#include "transport/conn/loop/connrunner/level.c"
#include "transport/conn/loop/crecv/collect.c"
#include "transport/conn/loop/manage/zerortt_policy.c"
#include "transport/conn/loop/manage/zerortt_seen.c"
#include "transport/packet/build/hspkt/hspkt_open.c"
#include "transport/packet/build/hspkt/onertt.c"
#include "transport/packet/build/hspkt/unprotect.c"
#include "transport/packet/build/initpkt/initkeys.c"
#include "transport/packet/build/initpkt/initopen.c"
#include "transport/packet/build/vpn/vpn_open.c"
#include "transport/packet/frame/frame/ack.c"
#include "transport/packet/frame/frame/ack_take.c"
#include "transport/packet/frame/frame/connctl.c"
#include "transport/packet/frame/frame/dispatch.c"
#include "transport/packet/frame/frame/flowctl.c"
#include "transport/packet/frame/frame/frame.c"
#include "transport/packet/frame/frame/frame_take.c"
#include "transport/packet/frame/frame/ncid.c"
#include "transport/packet/frame/frame/stream_bounds.c"
#include "transport/packet/frame/frame/stream_ctl.c"
#include "transport/packet/frame/pipeline/framewalk.c"
#include "transport/packet/frame/pipeline/rxpacket.c"
#include "transport/packet/header/lhdr/lhdr_parse.c"
#include "transport/packet/header/packet/coalesce.c"
#include "transport/packet/header/packet/header.c"
#include "transport/packet/header/packet/inittoken.c"
#include "transport/packet/header/packet/pnum.c"
#include "transport/packet/header/packet/ptype.c"
#include "transport/packet/protect/hp/hp.c"
#include "transport/packet/protect/hp/hp_chacha.c"
#include "transport/packet/protect/hp/hpapply.c"
#include "transport/packet/protect/hp/hpsample.c"
#include "transport/packet/protect/protect/protect.c"
#include "transport/packet/protect/protect_suite/aead_suite.c"
#include "transport/packet/protect/protect_suite/hp_suite.c"
#include "transport/version/version/availfilter.c"
#include "transport/version/version/compat.c"
#include "transport/version/version/v2keys.c"
#include "transport/version/version/v2types.c"
#include "transport/version/version/verinfo.c"
#include "transport/version/version/verselect.c"
#include "transport/version/version/version.c"
#include "transport/version/versmgr/avail.c"

/* wired_srvloop_recv opens in place (header protection removal, then AEAD),
 * but libFuzzer's input is `const` -- copy each packet into a scratch
 * buffer first, as a real UDP receive would hand the step its own read
 * buffer. A packet longer than the scratch buffer is skipped: no valid QUIC
 * packet is anywhere near that size. */
#define SCRATCH_CAP 4096

static wired_server g_srv;

/* A server whose 1-RTT keys are installed (zero key material) and whose
 * connection ID is 8 bytes, negotiated on QUIC v1 with AES-128-GCM. */
static void arm(wired_server* s) {
  memset(s, 0, sizeof *s);
  s->sdrv.cipher_suite = TLS_AES_128_GCM_SHA256;
  s->sdrv.iscid_len    = 8;
  s->sdrv.odcid_len    = 8;
}

static void feed_one(wired_server* s, const u8* data, usz len) {
  static u8              scratch[SCRATCH_CAP];
  wired_srvloop_recv_out out;
  wired_srvloop_recv_in  in;
  if (len == 0 || len > SCRATCH_CAP) {
    return;
  }
  memcpy(scratch, data, len);
  in = (wired_srvloop_recv_in){wired_mspan_of(scratch, len), 0, 0};
  wired_srvloop_recv(s, &in, &out);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  coalesce_iter it;
  coalesced     pkt;
  arm(&g_srv);
  /* RFC 9000 12.2: coalesce_next consumes the cursor on every yield (or
   * stops), so this loop is bounded by the input length. */
  coalesce_begin(&it, (const u8*)data, (usz)size);
  while (coalesce_next(&it, &pkt)) {
    feed_one(&g_srv, pkt.data, pkt.len);
  }
  return 0;
}
