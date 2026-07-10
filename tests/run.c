/* Unity build: every production .c MUST be included before the *_test.c that
 * uses its symbols, or the test sees an undeclared identifier. clang-format
 * SortIncludes (default on) would re-sort these alphabetically and interleave
 * each test with its source, breaking the build — keep it off for this block.
 */
// clang-format off
#include "test.h"
#include "transport/recovery/detect/ackrange/ackrange_process.c"
#include "app/datagram/dgdeliver/dg_send.c"
#include "app/datagram/dgdeliver/dg_loss.c"
#include "app/datagram/dgdeliver/dg_recv.c"
#include "transport/recovery/detect/losstime/losstime.c"
#include "transport/conn/pnspace/pnspaces/spaces.c"
#include "transport/conn/pnspace/pnspaces/sent_spaces.c"
#include "transport/conn/pnspace/pnspaces/recv_spaces.c"
#include "transport/packet/protect/protectcs/protectcs.c"
#include "transport/packet/header/shorthdr/shorthdr.c"
#include "transport/version/versmgr/avail.c"
#include "transport/version/versmgr/v2switch.c"
#include "transport/version/versmgr/downgrade.c"
#include "crypto/pki/cert/certreq/certreq.c"
#include "transport/recovery/congestion/cwndctl/cwndctl.c"
#include "tls/handshake/core/hrr/hrr_build.c"
#include "tls/handshake/core/hrr/hrr_detect.c"
#include "tls/handshake/core/hrr/hrr_group.c"
#include "tls/ext/legacy/legacy_fields.c"
#include "transport/stream/data/maxstreams/maxstreams.c"
#include "transport/io/socket/poll/deadline.c"
#include "transport/io/socket/poll/nonblock.c"
#include "transport/io/socket/poll/wait.c"
#include "app/qpack/qpackdyn/insert_encode.c"
#include "app/qpack/qpackdyn/field_encode.c"
#include "app/qpack/qpackdyn/field_decode.c"
#include "tls/ext/tlsext/pskmodes.c"
#include "tls/ext/tlsext/preshared.c"
#include "tls/ext/tlsext/earlydata.c"
#include "tls/handshake/roles/shbuild/shbuild.c"
#include "tls/handshake/roles/sflight/encext.c"
#include "tls/handshake/roles/sflight/certmsg.c"
#include "tls/handshake/roles/sflight/certverify_build.c"
#include "tls/handshake/roles/sflight/finished_build.c"
#include "transport/packet/build/initpkt/initkeys.c"
#include "transport/packet/build/initpkt/initpkt.c"
#include "transport/packet/build/initpkt/initopen.c"
#include "transport/conn/lifecycle/idledrive/idledrive.c"
#include "transport/conn/lifecycle/idledrive/idlenego.c"
#include "transport/conn/lifecycle/idledrive/closesend.c"
#include "transport/conn/cid/sresetdrive/detect.c"
#include "transport/conn/cid/sresetdrive/tokenmap.c"
#include "transport/conn/cid/sresetdrive/onreset.c"
#include "app/http3/request/h3req/reqorder.c"
#include "app/http3/request/h3req/reqbuild.c"
#include "app/http3/request/h3req/respparse.c"
#include "transport/stream/flow/flowviol/flowviol.c"
#include "transport/stream/flow/flowviol/closeframe.c"
#include "tls/ext/tpverify/odcid.c"
#include "tls/ext/tpverify/iscid.c"
#include "tls/ext/tpverify/rscid.c"
#include "tls/handshake/core/fullhs/fullhs.c"
#include "tls/handshake/core/tlsdriver/tlsdriver.c"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.c"
#include "transport/conn/pnspace/crypto_stream/crypto_rx.c"
#include "transport/conn/pnspace/crypto_stream/ecdhe.c"
#include "app/http3/core/h3run/control.c"
#include "app/http3/core/h3run/settings_seq.c"
#include "app/http3/core/h3run/goaway.c"
#include "tls/handshake/core/handshake_drive/retry_drive.c"
#include "tls/handshake/core/handshake_drive/vn_drive.c"
#include "transport/packet/protect/protect_suite/aead_suite.c"
#include "transport/packet/protect/protect_suite/hp_suite.c"
#include "tls/keys/schedule_drive/keyschedule.c"
#include "transport/recovery/rtx/sentpkt/sentpkt.c"
#include "transport/recovery/rtx/sentpkt/ack_process.c"
#include "transport/recovery/rtx/sentpkt/loss_detect.c"
#include "crypto/kdf/keys/discard_driver.c"
#include "crypto/kdf/keys/promote.c"
#include "crypto/kdf/keys/keyset.c"
#include "transport/packet/frame/pipeline/framewalk.c"
#include "transport/packet/frame/pipeline/rxpacket.c"
#include "transport/packet/frame/pipeline/txpacket.c"
#include "tls/handshake/core/tls/hsdriver.c"
#include "tls/handshake/core/tls/certverify.c"
#include "crypto/pki/encoding/x509/ec_pubkey.c"
#include "crypto/pki/encoding/x509/rsa_pubkey.c"
#include "crypto/asymmetric/rsa/rsa_pss_verify.c"
#include "crypto/asymmetric/rsa/pss.c"
#include "crypto/asymmetric/rsa/mgf1.c"
#include "tls/handshake/core/tls/serverhello.c"
#include "tls/handshake/core/tls/clienthello.c"
#include "tls/handshake/core/tls/ext_keyshare.c"
#include "crypto/pki/encoding/x509/validity.c"
#include "crypto/pki/encoding/x509/spki.c"
#include "crypto/pki/encoding/x509/x509.c"
#include "crypto/asymmetric/ecc/p256/ecdsa_verify.c"
#include "crypto/asymmetric/ecc/p256/p256_point.c"
#include "crypto/asymmetric/ecc/p256/p256_field.c"
#include "crypto/asymmetric/ecc/p384/p384_field.c"
#include "crypto/asymmetric/ecc/p384/p384_point.c"
#include "crypto/asymmetric/ecc/p384/ecdsa_verify.c"
#include "crypto/asymmetric/rsa/rsa_verify.c"
#include "crypto/asymmetric/bignum/modexp.c"
#include "crypto/asymmetric/bignum/bignum.c"
#include "tls/handshake/core/tls/hs_message.c"
#include "tls/handshake/core/tls/transcript_stage.c"
#include "tls/handshake/core/tls/transcript.c"
#include "tls/handshake/core/tls/ext_block.c"
#include "tls/handshake/core/tls/ext_algs.c"
#include "tls/handshake/core/tls/ext_versions.c"
#include "tls/handshake/core/tls/hp_select.c"
#include "tls/handshake/core/tls/aead_params.c"
#include "tls/handshake/core/tls/cipher.c"
#include "common/platform/clock/clock.c"
#include "common/platform/clock/mono.c"
#include "common/platform/debug/debug.c"
#include "common/platform/fio/fio.c"
#include "common/platform/qlog/qlog.c"
#include "common/platform/qlog/qlogevent.c"
#include "common/platform/keylog/keylog.c"
#include "common/platform/cliargs/cliargs.c"
#include "common/platform/rng/challenge.c"
#include "common/platform/rng/cidgen.c"
#include "common/platform/rng/rng.c"
#include "transport/io/socket/io/udptransport.c"
#include "transport/io/socket/io/addr.c"
#include "crypto/pki/encoding/asn1/derval.c"
#include "crypto/pki/encoding/asn1/derseq.c"
#include "crypto/pki/encoding/asn1/der.c"
#include "crypto/pki/encoding/pem/pem.c"
#include "crypto/pki/encoding/eckey/eckey.c"
#include "transport/conn/lifecycle/session/session.c"
#include "app/datagram/datagram/zerortt_dgram.c"
#include "tls/handshake/core/tls/ticketversion.c"
#include "transport/version/version/switchrule.c"
#include "tls/handshake/core/tls/alpn_match.c"
#include "tls/handshake/core/tls/alpn.c"
#include "tls/handshake/core/tls/sni.c"
#include "app/http3/core/h3/reuse.c"
#include "transport/conn/lifecycle/closelife/keepalive.c"
#include "app/http3/core/h3/priority.c"
#include "app/http3/core/h3/priupdate.c"
#include "crypto/symmetric/hash/hash/sha512.c"
#include "crypto/symmetric/hash/hash/sha384.c"
#include "crypto/pki/encoding/x509/sigalgoid.c"
#include "app/qpack/qpack/base.c"
#include "app/qpack/qpack/fieldline.c"
#include "app/qpack/qpack/insertcount.c"
#include "app/qpack/qpack/literal.c"
#include "app/qpack/qpack/relindex.c"
#include "crypto/symmetric/aead/aes/aes.c"
#include "transport/recovery/congestion/cc/cc.c"
#include "transport/recovery/congestion/cc/bbr.c"
#include "transport/recovery/congestion/cc/cubic.c"
#include "transport/recovery/congestion/cc/hystart.c"
#include "transport/recovery/congestion/cc/ccloss.c"
#include "transport/recovery/congestion/cc/ccphase.c"
#include "transport/recovery/congestion/cc/cwndcheck.c"
#include "transport/recovery/congestion/cc/ecn.c"
#include "transport/recovery/congestion/cc/pacing.c"
#include "transport/recovery/congestion/cc/persistent.c"
#include "crypto/symmetric/aead/chacha/aead.c"
#include "crypto/symmetric/aead/chacha/chacha20.c"
#include "crypto/symmetric/aead/chacha/poly1305.c"
#include "transport/conn/cid/cid/cidpool.c"
#include "transport/conn/lifecycle/closelife/closelife.c"
#include "transport/conn/lifecycle/closelife/draining.c"
#include "transport/conn/lifecycle/closelife/idlefloor.c"
#include "transport/conn/lifecycle/closelife/idletimeout.c"
#include "transport/conn/lifecycle/closelife/termgate.c"
#include "transport/conn/lifecycle/conn/cidnego.c"
#include "transport/conn/cid/cidxchg/cidxchg.c"
#include "transport/conn/lifecycle/conn/conn.c"
#include "transport/conn/lifecycle/conn/demux.c"
#include "transport/conn/lifecycle/conn/pnspace.c"
#include "transport/conn/lifecycle/conntable/conntable.c"
#include "app/datagram/datagram/datagram.c"
#include "app/datagram/datagram/dgcc.c"
#include "app/datagram/datagram/dgcheck.c"
#include "app/datagram/datagram/dgsize.c"
#include "crypto/asymmetric/ecc/ed25519/ed25519_field.c"
#include "crypto/asymmetric/ecc/ed25519/ed25519_sign.c"
#include "transport/conn/lifecycle/endpoint/endpoint.c"
#include "common/diag/error/codes.c"
#include "common/diag/error/error.c"
#include "transport/stream/flow/flow/dual_flow.c"
#include "transport/stream/flow/flow/finalsize.c"
#include "transport/stream/flow/flow/flow.c"
#include "transport/stream/flow/flow/reassemble.c"
#include "transport/stream/flow/flow/stream_flow.c"
#include "transport/stream/flow/flow/streams.c"
#include "transport/packet/frame/frame/ack.c"
#include "transport/packet/frame/frame/ack_range.c"
#include "transport/packet/frame/frame/close_convert.c"
#include "transport/packet/frame/frame/connctl.c"
#include "transport/packet/frame/frame/crypto_offset.c"
#include "transport/packet/frame/frame/dispatch.c"
#include "transport/packet/frame/frame/flowctl.c"
#include "transport/packet/frame/frame/frame.c"
#include "transport/packet/frame/frame/ncid.c"
#include "transport/packet/frame/frame/ncid_check.c"
#include "transport/packet/frame/frame/ncid_worker.c"
#include "transport/packet/frame/frame/permit.c"
#include "transport/packet/frame/frame/stream_bounds.c"
#include "transport/packet/frame/frame/stream_ctl.c"
#include "transport/conn/lifecycle/fsm/fsm.c"
#include "crypto/symmetric/aead/gcm/gcm.c"
#include "tls/ext/grease/bitset.c"
#include "tls/ext/grease/early.c"
#include "tls/ext/grease/grease.c"
#include "tls/ext/grease/sreset_bit.c"
#include "app/http3/core/h3/connect.c"
#include "app/http3/core/h3/contentlen.c"
#include "app/http3/core/h3/control.c"
#include "app/http3/core/h3/critical.c"
#include "app/http3/core/h3/errclass.c"
#include "app/http3/core/h3/fieldsize.c"
#include "app/http3/core/h3/firstframe.c"
#include "app/http3/core/h3/frame.c"
#include "app/http3/core/h3/frame_permit.c"
#include "app/http3/core/h3/goaway_check.c"
#include "app/http3/core/h3/grease.c"
#include "app/http3/core/h3/h3dgram.c"
#include "app/http3/core/h3/headercase.c"
#include "app/http3/core/h3/pseudoheader.c"
#include "app/http3/core/h3/pushid.c"
#include "app/http3/core/h3/qpack_settings.c"
#include "app/http3/core/h3/reqstream.c"
#include "app/http3/core/h3/settings_check.c"
#include "app/http3/core/h3/settings_dup.c"
#include "app/http3/core/h3/shutdown.c"
#include "app/http3/core/h3/stream_type.c"
#include "crypto/symmetric/hash/hash/hmac.c"
#include "crypto/symmetric/hash/hash/sha256.c"
#include "crypto/kdf/hkdf/hkdf.c"
#include "transport/packet/protect/hp/hp.c"
#include "transport/packet/protect/hp/hp_chacha.c"
#include "transport/packet/protect/hp/hpapply.c"
#include "transport/packet/protect/hp/hpsample.c"
#include "transport/io/socket/io/retransmit.c"
#include "transport/io/socket/io/udp.c"
#include "tls/keys/keyupdate/aeadlimit.c"
#include "tls/keys/keyupdate/initiate.c"
#include "tls/keys/keyupdate/keyphase.c"
#include "tls/keys/keyupdate/keyupdate.c"
#include "tls/keys/keyupdate/kuderive.c"
#include "tls/keys/keyupdate/oldkey.c"
#include "tls/keys/ticket/ticket.c"
#include "tls/keys/ticketguard/ticketguard.c"
#include "transport/conn/loop/manage/dosmitigate.c"
#include "transport/conn/loop/manage/flowobs.c"
#include "transport/conn/loop/manage/linkability.c"
#include "transport/conn/loop/manage/middlebox.c"
#include "transport/conn/loop/manage/observable.c"
#include "transport/conn/loop/manage/rttobs.c"
#include "transport/conn/loop/manage/zerortt_policy.c"
#include "transport/conn/cid/migrate/migrate.c"
#include "transport/io/socket/net/checksum.c"
#include "transport/io/socket/net/eth.c"
#include "transport/io/socket/net/ipv4.c"
#include "transport/io/socket/net/memlink.c"
#include "transport/io/socket/net/udp4.c"
#include "transport/io/xdp/xdpmac/xdpmac.c"
#include "transport/io/xdp/xdpbpf/xdpbpf.c"
#include "transport/io/xdp/xskring/xskring.c"
#include "transport/io/xdp/xskumem/xskumem.c"
#include "transport/io/xdp/xsksetup/xsksetup.c"
#include "transport/io/xdp/xdpframe/xdpframe.c"
#include "transport/packet/header/packet/coalesce.c"
#include "transport/packet/header/packet/coalorder.c"
#include "transport/packet/header/packet/header.c"
#include "transport/packet/header/dcidresolve/dcidresolve.c"
#include "transport/packet/header/packet/inittoken.c"
#include "transport/packet/header/packet/pad.c"
#include "transport/packet/header/packet/pnlen.c"
#include "transport/packet/header/packet/pnum.c"
#include "transport/packet/header/packet/ptype.c"
#include "transport/packet/header/packet/resbits.c"
#include "transport/packet/header/packet/retry.c"
#include "transport/packet/header/packet/short.c"
#include "transport/packet/header/packet/vneg.c"
#include "transport/conn/cid/path/antiamp.c"
#include "transport/conn/cid/path/path.c"
#include "transport/conn/cid/path/prefaddr.c"
#include "transport/conn/cid/pmtu/pmtu.c"
#include "transport/packet/protect/protect/protect.c"
#include "app/qpack/qpack/huffman.c"
#include "app/qpack/qpack/instruction.c"
#include "app/qpack/qpack/integer.c"
#include "app/qpack/qpack/prefix.c"
#include "app/qpack/qpack/static_table.c"
#include "app/qpack/qpack/string.c"
#include "transport/recovery/detect/recovery/ackdelay.c"
#include "transport/recovery/detect/recovery/ackpolicy.c"
#include "transport/recovery/detect/recovery/inflight.c"
#include "transport/recovery/detect/recovery/largestacked.c"
#include "transport/recovery/detect/recovery/lossdetect.c"
#include "transport/recovery/detect/recovery/losstimer.c"
#include "transport/recovery/detect/recovery/probe.c"
#include "transport/recovery/detect/recovery/pto.c"
#include "transport/recovery/detect/recovery/ptoreset.c"
#include "transport/recovery/detect/recovery/rtt.c"
#include "transport/recovery/detect/recovery/rttinit.c"
#include "transport/recovery/detect/recovery/rttsample.c"
#include "transport/recovery/detect/recovery/rttvalid.c"
#include "transport/recovery/detect/recovery/sent.c"
#include "transport/recovery/stats/stats.c"
#include "transport/conn/pnspace/recvpn/recvpn.c"
#include "transport/conn/cid/retrytoken/retrytoken.c"
#include "transport/conn/cid/retrytoken/tokentype.c"
#include "transport/conn/cid/spin/spin.c"
#include "transport/conn/cid/sreset/sreset.c"
#include "transport/stream/data/stream/bidi.c"
#include "transport/stream/data/stream/stream.c"
#include "transport/stream/data/stream/stream_id.c"
#include "transport/stream/data/stream/stream_limit.c"
#include "transport/stream/data/stream/stream_role.c"
#include "tls/handshake/core/tls/appkeys.c"
#include "tls/handshake/core/tls/cert.c"
#include "tls/handshake/core/tls/encext_check.c"
#include "tls/handshake/core/tls/finished.c"
#include "tls/handshake/core/tls/handshake.c"
#include "tls/handshake/core/tls/hsdone.c"
#include "tls/handshake/core/tls/initial.c"
#include "tls/handshake/core/tls/newsessionticket.c"
#include "tls/handshake/core/tls/keydiscard.c"
#include "tls/handshake/core/tls/master.c"
#include "tls/handshake/core/tls/msgassembly.c"
#include "tls/handshake/core/tls/retry_tag.c"
#include "tls/handshake/core/tls/retry_tag_v2.c"
#include "tls/handshake/core/tls/schedule.c"
#include "tls/handshake/core/tls/tpext.c"
#include "tls/handshake/core/tls/x25519.c"
#include "tls/handshake/core/tls/zerortt_params.c"
#include "tls/handshake/core/tls/zerortt_reject.c"
#include "tls/ext/tparam/tparam.c"
#include "tls/ext/tparam/tpblob.c"
#include "tls/ext/tparam/tpcheck.c"
#include "common/bytes/varint/varint.c"
#include "transport/version/version/abandon.c"
#include "transport/version/version/availfilter.c"
#include "transport/version/version/compat.c"
#include "transport/version/version/compatnego.c"
#include "transport/version/version/downgrade.c"
#include "transport/version/version/v2keys.c"
#include "transport/version/version/v2types.c"
#include "transport/version/version/verinfo.c"
#include "transport/version/version/verselect.c"
#include "transport/version/version/version.c"
#include "transport/version/version/vneg.c"
#include "crypto/pki/encoding/x509/chain.c"
#include "crypto/pki/encoding/x509/basicconstraints.c"
#include "crypto/pki/encoding/x509/san.c"
#include "transport/conn/lifecycle/connection/connection.c"
#include "app/qpack/qpack/dyntable.c"
#include "app/qpack/qpack/dynget.c"
#include "app/qpack/qpack/dynfind.c"
#include "transport/stream/flow/flow/stream_read.c"
#include "transport/stream/flow/flow/credit.c"
#include "transport/stream/flow/flow/stream_credit.c"
#include "transport/packet/frame/framedispatch/dispatch_state.c"
#include "transport/io/udp/udploop/rxloop.c"
#include "transport/io/udp/udploop/txloop.c"
#include "transport/io/udp/udploop/antiamp_gate.c"
#include "transport/conn/loop/connloop/connloop.c"
#include "transport/conn/loop/connio/connio.c"
#include "transport/recovery/detect/lossdrive/lossdrive.c"
#include "transport/recovery/detect/lossdrive/lossdelay.c"
#include "transport/recovery/detect/lossdrive/ptobackoff.c"
#include "transport/packet/build/pktbuild/initpad.c"
#include "transport/packet/build/pktbuild/framepack.c"
#include "transport/packet/build/pktbuild/eliciting.c"
#include "transport/recovery/detect/ackgen/ackgen.c"
#include "transport/recovery/detect/ackgen/ackrange.c"
#include "transport/recovery/detect/ackgen/ackfreq.c"
#include "crypto/pki/trust/castore/castore.c"
#include "crypto/pki/trust/castore/chainverify.c"
#include "crypto/pki/trust/castore/pathvalidate.c"
#include "transport/conn/loop/driver/driver.c"
#include "tls/handshake/roles/client/client.c"
#include "tls/handshake/core/sdrv/sdrv.c"
#include "tls/handshake/core/sdrv/sdrv_flight.c"
#include "crypto/pki/cert/selfcert/derenc.c"
#include "crypto/pki/cert/selfcert/tbs.c"
#include "crypto/pki/cert/selfcert/selfcert.c"
#include "transport/packet/build/hspkt/hspkt_build.c"
#include "transport/packet/build/hspkt/hspkt_open.c"
#include "transport/packet/build/hspkt/onertt.c"
#include "transport/packet/build/hspkt/unprotect.c"
#include "tls/handshake/roles/srvfin/verify.c"
#include "tls/handshake/roles/srvfin/complete.c"
#include "tls/handshake/roles/srvfin/hsdone.c"
#include "tls/ext/salpn/ch_ext.c"
#include "tls/ext/salpn/negotiate.c"
#include "tls/ext/salpn/sni_extract.c"
#include "tls/ext/stp/server_tp.c"
#include "tls/ext/stp/parse_tp.c"
#include "app/http3/core/h3settings/control_open.c"
#include "app/http3/core/h3settings/settings_build.c"
#include "app/http3/core/h3settings/control_settings.c"
#include "app/http3/core/capsule/capsule.c"
#include "transport/packet/header/lhdr/lhdr_build.c"
#include "transport/packet/header/lhdr/lhdr_parse.c"
#include "transport/packet/build/vpn/vpn_open.c"
#include "transport/stream/data/appdata/stream_send.c"
#include "transport/stream/data/appdata/app_send.c"
#include "transport/stream/data/appdata/app_recv.c"
#include "app/http3/request/h3recv/req_frames.c"
#include "app/http3/request/h3resp/field_encode.c"
#include "app/http3/request/h3resp/resp_build.c"
#include "app/http3/request/h3resp/hello.c"
#include "transport/conn/loop/evloop/evloop.c"
#include "transport/conn/loop/connrunner/level.c"
#include "transport/conn/loop/connrunner/recv.c"
#include "transport/conn/loop/connrunner/send.c"
#include "transport/conn/loop/connrunner/keyupdate.c"
#include "transport/conn/loop/connrunner/reconnect.c"
#include "transport/conn/loop/connrunner/connrunner.c"
#include "app/http3/core/h3conn/establish.c"
#include "app/http3/core/h3conn/request.c"
#include "app/http3/core/h3conn/response.c"
#include "app/http3/request/h3reqdrive/request_parse.c"
#include "app/http3/request/h3reqdrive/request_drive.c"
#include "app/http3/request/h3cancel/cancel.c"
#include "transport/recovery/rtx/rtxbytes/rtxstore.c"
#include "transport/recovery/rtx/rtxbytes/rebuild.c"
#include "transport/recovery/rtx/rtxbytes/collect.c"
#include "tls/keys/kuswitch/derive.c"
#include "tls/keys/kuswitch/phasebit.c"
#include "tls/keys/kuswitch/twogen.c"
#include "transport/recovery/detect/hspto/hspto.c"
#include "transport/recovery/detect/hspto/arm.c"
#include "transport/recovery/detect/hspto/probe_space.c"
#include "app/http3/request/h3reqenc/pseudo_encode.c"
#include "app/http3/request/h3reqenc/header_encode.c"
#include "app/http3/request/h3reqenc/request_headers.c"
#include "crypto/pki/cert/tbscert/fields.c"
#include "crypto/pki/cert/tbscert/version_serial.c"
#include "crypto/pki/cert/tbscert/sigalg.c"
#include "transport/recovery/rtx/rtxdrive/select.c"
#include "transport/recovery/rtx/rtxdrive/build.c"
#include "transport/recovery/rtx/rtxdrive/batch.c"
#include "tls/keys/kudrive/trigger.c"
#include "tls/keys/kudrive/recv_phase.c"
#include "tls/keys/kudrive/discard_timing.c"
#include "transport/conn/cid/retrydrive/accept.c"
#include "transport/conn/cid/retrydrive/reconnect.c"
#include "transport/conn/cid/retrydrive/token.c"
#include "transport/version/vndrive/accept.c"
#include "transport/version/vndrive/select.c"
#include "transport/version/vndrive/reconnect.c"
#include "transport/recovery/rtx/sentmeta/record.c"
#include "transport/recovery/rtx/sentmeta/on_ack.c"
#include "transport/recovery/rtx/sentmeta/detect_loss.c"
#include "transport/io/udp/udpsess/udpsess.c"
#include "tls/ext/alpnver/alpnver.c"
#include "tls/handshake/flight/resume/resume.c"
#include "tls/handshake/flight/earlydrive/earlydata.c"
#include "crypto/asymmetric/ecc/p256sign/rfc6979.c"
#include "crypto/asymmetric/ecc/p256sign/sign.c"
#include "crypto/asymmetric/ecc/ecdsasig/der_int.c"
#include "crypto/asymmetric/ecc/ecdsasig/sig_value.c"
#include "crypto/pki/cert/p256cert/spki.c"
#include "crypto/pki/cert/p256cert/tbs.c"
#include "crypto/pki/cert/p256cert/p256cert.c"
#include "crypto/asymmetric/ecc/cvecdsa/signed.c"
#include "crypto/asymmetric/ecc/cvecdsa/cvecdsa.c"
#include "tls/handshake/roles/eebuild/eebuild.c"
#include "transport/conn/loop/crecv/collect.c"
#include "transport/conn/loop/crecv/message.c"
#include "tls/handshake/roles/server/server.c"
#include "tls/handshake/roles/server/serverio.c"
#include "app/http3/server/h3srv/control.c"
#include "app/http3/server/h3srv/peer.c"
#include "app/http3/server/h3srv/respond.c"
#include "app/http3/server/srvwire/wire.c"
#include "app/http3/server/srvloop/keys.c"
#include "app/http3/server/srvloop/recv.c"
#include "app/http3/server/srvloop/dispatch.c"
#include "app/http3/server/srvloop/send.c"
#include "app/http3/server/srvloop/respond.c"
#include "app/http3/server/sendq/sendq.c"
#include "app/http3/server/sendsess/sendsess.c"
#include "app/http3/server/srvloop/srvloop.c"
#include "app/http3/server/srvboot/srvboot.c"
#include "app/http3/server/sigterm/sigterm.c"
#include "app/http3/server/certreload/certreload.c"
#include "app/http3/server/srvrun/srvrun.c"
#include "app/http3/server/staticfile/staticfile.c"
#include "app/http3/server/mimetype/mimetype.c"
#include "app/http3/server/srvpin/srvpin.c"
#include "app/http3/server/srvworkers/srvworkers.c"
#include "app/http3/server/srvpoll/srvpoll.c"
#include "tls/handshake/roles/client/clientwire.c"
#include "app/webtransport/session/session/session.c"
#include "app/webtransport/errmap/errmap/errmap.c"
#include "app/webtransport/capsule/wtcapsule/wtcapsule.c"
#include "common/varint_test.c"
#include "transport/header_test.c"
#include "transport/dcidresolve_test.c"
#include "transport/pnum_test.c"
#include "tls/tparam_test.c"
#include "transport/frame_test.c"
#include "transport/stream_test.c"
#include "transport/conn_test.c"
#include "crypto/sha256_test.c"
#include "crypto/hmac_test.c"
#include "crypto/hkdf_test.c"
#include "crypto/aes_test.c"
#include "crypto/gcm_test.c"
#include "crypto/chacha20_test.c"
#include "crypto/poly1305_test.c"
#include "crypto/aead_test.c"
#include "tls/initial_test.c"
#include "transport/hp_test.c"
#include "transport/rtt_test.c"
#include "transport/sent_test.c"
#include "transport/cc_test.c"
#include "transport/flow_test.c"
#include "transport/udp_test.c"
#include "transport/udp_recvmmsg_test.c"
#include "transport/udp_recvfrom_test.c"
#include "transport/udp_gso_test.c"
#include "transport/retransmit_test.c"
#include "transport/ack_test.c"
#include "transport/ncid_test.c"
#include "transport/protect_test.c"
#include "transport/net_test.c"
#include "tls/x25519_test.c"
#include "tls/handshake_test.c"
#include "tls/schedule_test.c"
#include "transport/endpoint_test.c"
#include "transport/stream_ctl_test.c"
#include "transport/connctl_test.c"
#include "transport/dispatch_test.c"
#include "common/error_test.c"
#include "transport/packet2_test.c"
#include "transport/flowctl_test.c"
#include "transport/abandon_test.c"
#include "transport/ack_range_test.c"
#include "transport/ackdelay_test.c"
#include "transport/ackpolicy_test.c"
#include "tls/aeadlimit_test.c"
#include "transport/antiamp_test.c"
#include "tls/appkeys_test.c"
#include "transport/availfilter_test.c"
#include "app/base_test.c"
#include "app/bidi_test.c"
#include "tls/bitset_test.c"
#include "transport/ccloss_test.c"
#include "transport/ccphase_test.c"
#include "tls/cert_test.c"
#include "transport/cidnego_test.c"
#include "transport/cidxchg_test.c"
#include "transport/cidpool_test.c"
#include "transport/close_convert_test.c"
#include "transport/closelife_test.c"
#include "transport/coalesce_test.c"
#include "transport/coalorder_test.c"
#include "common/codes_test.c"
#include "transport/compat_test.c"
#include "transport/compatnego_test.c"
#include "app/connect_test.c"
#include "app/contentlen_test.c"
#include "app/critical_test.c"
#include "transport/crypto_offset_test.c"
#include "transport/cwndcheck_test.c"
#include "app/datagram_test.c"
#include "transport/demux_test.c"
#include "transport/conntable_test.c"
#include "transport/bbr_test.c"
#include "transport/cubic_test.c"
#include "transport/hystart_test.c"
#include "app/dgcc_test.c"
#include "app/dgcheck_test.c"
#include "app/dgsize_test.c"
#include "transport/dosmitigate_test.c"
#include "transport/downgrade_test.c"
#include "transport/draining_test.c"
#include "transport/dual_flow_test.c"
#include "tls/early_test.c"
#include "transport/ecn_test.c"
#include "crypto/ed25519_test.c"
#include "tls/encext_check_test.c"
#include "app/errclass_test.c"
#include "app/fieldline_test.c"
#include "app/fieldsize_test.c"
#include "transport/finalsize_test.c"
#include "tls/finished_test.c"
#include "app/firstframe_test.c"
#include "transport/flowobs_test.c"
#include "app/frame_permit_test.c"
#include "app/goaway_check_test.c"
#include "tls/grease_test.c"
#include "app/h3control_test.c"
#include "app/h3dgram_test.c"
#include "app/h3frame_test.c"
#include "app/h3grease_test.c"
#include "app/h3stream_type_test.c"
#include "app/headercase_test.c"
#include "transport/hp_chacha_test.c"
#include "transport/hpapply_test.c"
#include "transport/hpsample_test.c"
#include "tls/hsdone_test.c"
#include "transport/idlefloor_test.c"
#include "transport/idletimeout_test.c"
#include "transport/inflight_test.c"
#include "tls/initiate_test.c"
#include "transport/inittoken_test.c"
#include "app/insertcount_test.c"
#include "tls/keydiscard_test.c"
#include "tls/keyphase_test.c"
#include "tls/keyupdate_test.c"
#include "tls/kuderive_test.c"
#include "transport/largestacked_test.c"
#include "transport/linkability_test.c"
#include "app/literal_test.c"
#include "transport/lossdetect_test.c"
#include "transport/losstimer_test.c"
#include "tls/master_test.c"
#include "transport/middlebox_test.c"
#include "transport/migrate_test.c"
#include "tls/msgassembly_test.c"
#include "transport/ncid_check_test.c"
#include "transport/observable_test.c"
#include "tls/oldkey_test.c"
#include "transport/pacing_test.c"
#include "transport/pad_test.c"
#include "transport/path_test.c"
#include "transport/permit_test.c"
#include "transport/persistent_test.c"
#include "transport/pmtu_test.c"
#include "transport/pnlen_test.c"
#include "transport/pnspace_test.c"
#include "transport/prefaddr_test.c"
#include "transport/probe_test.c"
#include "app/pseudoheader_test.c"
#include "transport/pto_test.c"
#include "transport/ptoreset_test.c"
#include "transport/ptype_test.c"
#include "app/pushid_test.c"
#include "app/qpack_huffman_test.c"
#include "app/qpack_instruction_test.c"
#include "app/qpack_prefix_test.c"
#include "app/qpack_settings_test.c"
#include "app/qpack_test.c"
#include "transport/recvpn_test.c"
#include "app/relindex_test.c"
#include "app/reqstream_test.c"
#include "transport/resbits_test.c"
#include "tls/retry_tag_test.c"
#include "tls/retry_tag_v2_test.c"
#include "transport/retrytoken_test.c"
#include "transport/rttinit_test.c"
#include "transport/rttobs_test.c"
#include "transport/rttsample_test.c"
#include "transport/rttvalid_test.c"
#include "app/settings_check_test.c"
#include "app/settings_dup_test.c"
#include "app/shutdown_test.c"
#include "transport/spin_test.c"
#include "tls/sreset_bit_test.c"
#include "transport/sreset_test.c"
#include "transport/stream_bounds_test.c"
#include "transport/stream_flow_test.c"
#include "transport/stream_id_test.c"
#include "transport/stream_limit_test.c"
#include "transport/stream_role_test.c"
#include "transport/streams_test.c"
#include "transport/tokentype_test.c"
#include "tls/tpblob_test.c"
#include "tls/tpcheck_test.c"
#include "tls/tpext_test.c"
#include "transport/v2keys_test.c"
#include "transport/v2types_test.c"
#include "transport/verinfo_test.c"
#include "transport/verselect_test.c"
#include "transport/version_test.c"
#include "transport/vneg_test.c"
#include "tls/zerortt_params_test.c"
#include "transport/zerortt_policy_test.c"
#include "tls/zerortt_reject_test.c"
#include "app/priority_test.c"
#include "transport/keepalive_test.c"
#include "app/reuse_test.c"
#include "tls/sni_test.c"
#include "tls/alpn_test.c"
#include "tls/alpn_match_test.c"
#include "transport/switchrule_test.c"
#include "tls/ticketversion_test.c"
#include "tls/ticket_test.c"
#include "tls/newsessionticket_test.c"
#include "app/zerortt_dgram_test.c"
#include "transport/session_test.c"
#include "crypto/der_test.c"
#include "crypto/derseq_test.c"
#include "crypto/derval_test.c"
#include "crypto/pem_test.c"
#include "crypto/eckey_test.c"
#include "common/fio_test.c"
#include "common/qlog_test.c"
#include "common/qlogevent_test.c"
#include "common/keylog_test.c"
#include "common/cliargs_test.c"
#include "transport/addr_test.c"
#include "transport/udptransport_test.c"
#include "common/clock_test.c"
#include "common/debug_test.c"
#include "common/rng_test.c"
#include "common/cidgen_test.c"
#include "common/challenge_test.c"
#include "tls/cipher_test.c"
#include "tls/aead_params_test.c"
#include "tls/hp_select_test.c"
#include "tls/ext_versions_test.c"
#include "tls/ext_algs_test.c"
#include "tls/ext_block_test.c"
#include "tls/transcript_test.c"
#include "tls/transcript_stage_test.c"
#include "tls/hs_message_test.c"
#include "crypto/bignum_test.c"
#include "crypto/modexp_test.c"
#include "crypto/rsa_verify_test.c"
#include "crypto/sha384_test.c"
#include "crypto/sigalgoid_test.c"
#include "crypto/rsachain_test.c"
#include "crypto/p256_field_test.c"
#include "crypto/p384_field_test.c"
#include "crypto/p384_point_test.c"
#include "crypto/ecdsa_p384_verify_test.c"
#include "crypto/p384chain_test.c"
#include "crypto/p256_point_test.c"
#include "crypto/ecdsa_verify_test.c"
#include "crypto/x509_test.c"
#include "crypto/spki_test.c"
#include "crypto/validity_test.c"
#include "tls/ext_keyshare_test.c"
#include "tls/clienthello_test.c"
#include "tls/serverhello_test.c"
#include "crypto/mgf1_test.c"
#include "crypto/rsa_pss_test.c"
#include "crypto/rsa_pubkey_test.c"
#include "crypto/ec_pubkey_test.c"
#include "tls/certverify_test.c"
#include "tls/hsdriver_test.c"
#include "transport/txpacket_test.c"
#include "transport/rxpacket_test.c"
#include "transport/framewalk_test.c"
#include "crypto/keyset_test.c"
#include "crypto/promote_test.c"
#include "crypto/discard_driver_test.c"
#include "crypto/chain_test.c"
#include "crypto/basicconstraints_test.c"
#include "crypto/san_test.c"
#include "transport/connection_test.c"
#include "app/dyntable_test.c"
#include "app/dynget_test.c"
#include "app/dynfind_test.c"
#include "transport/stream_read_test.c"
#include "transport/credit_test.c"
#include "transport/stream_credit_test.c"
#include "app/h3run_control_test.c"
#include "app/h3run_settings_seq_test.c"
#include "app/h3run_goaway_test.c"
#include "tls/retry_drive_test.c"
#include "tls/vn_drive_test.c"
#include "transport/aead_suite_test.c"
#include "transport/hp_suite_test.c"
#include "tls/keyschedule_test.c"
#include "transport/sentpkt_test.c"
#include "transport/ack_process_test.c"
#include "transport/loss_detect_test.c"
#include "transport/dispatch_state_test.c"
#include "transport/rxloop_test.c"
#include "transport/txloop_test.c"
#include "transport/antiamp_gate_test.c"
#include "transport/connloop_test.c"
#include "transport/connio_test.c"
#include "transport/lossdrive_test.c"
#include "transport/lossdelay_test.c"
#include "transport/ptobackoff_test.c"
#include "transport/initpad_test.c"
#include "transport/framepack_test.c"
#include "transport/eliciting_test.c"
#include "transport/ackgen_test.c"
#include "transport/ackrange_test.c"
#include "transport/ackfreq_test.c"
#include "crypto/castore_test.c"
#include "crypto/chainverify_test.c"
#include "crypto/pathvalidate_test.c"
#include "transport/driver_test.c"
#include "transport/crypto_stream_test.c"
#include "tls/tlsdriver_test.c"
#include "tls/fullhs_test.c"
#include "tls/fullhs_policy_test.c"
#include "tls/cert_chain_test.c"
#include "tls/fullhs_chain_test.c"
#include "tls/tlsdriver_sni_test.c"
#include "tls/client_test.c"
#include "transport/idledrive_test.c"
#include "transport/idlenego_test.c"
#include "transport/closesend_test.c"
#include "transport/sresetdrive_detect_test.c"
#include "transport/sresetdrive_tokenmap_test.c"
#include "transport/sresetdrive_onreset_test.c"
#include "app/reqorder_test.c"
#include "app/reqbuild_test.c"
#include "app/respparse_test.c"
#include "transport/flowviol_test.c"
#include "transport/closeframe_test.c"
#include "tls/odcid_test.c"
#include "tls/iscid_test.c"
#include "tls/rscid_test.c"
#include "transport/initpkt_test.c"
#include "crypto/ed25519_sign_test.c"
#include "tls/shbuild_test.c"
#include "tls/sflight_encext_test.c"
#include "tls/sflight_certmsg_test.c"
#include "tls/sflight_certverify_build_test.c"
#include "tls/sflight_finished_build_test.c"
#include "tls/sdrv_test.c"
#include "crypto/selfcert_test.c"
#include "transport/hspkt_build_test.c"
#include "transport/onertt_test.c"
#include "tls/srvfin_verify_test.c"
#include "tls/srvfin_complete_test.c"
#include "tls/srvfin_hsdone_test.c"
#include "tls/ch_ext_test.c"
#include "tls/negotiate_test.c"
#include "tls/sni_extract_test.c"
#include "tls/server_tp_test.c"
#include "app/h3settings_control_open_test.c"
#include "app/h3settings_build_test.c"
#include "app/h3settings_control_settings_test.c"
#include "app/capsule_test.c"
#include "transport/lhdr_build_test.c"
#include "transport/lhdr_parse_test.c"
#include "transport/vpn_open_test.c"
#include "transport/stream_send_test.c"
#include "transport/app_send_test.c"
#include "transport/app_recv_test.c"
#include "app/req_frames_test.c"
#include "app/field_encode_test.c"
#include "app/resp_build_test.c"
#include "app/hello_test.c"
#include "crypto/certreq_test.c"
#include "transport/cwndctl_test.c"
#include "tls/hrr_build_test.c"
#include "tls/hrr_detect_test.c"
#include "tls/hrr_group_test.c"
#include "tls/legacy_fields_test.c"
#include "transport/maxstreams_test.c"
#include "transport/poll_test.c"
#include "app/insert_encode_test.c"
#include "app/qpackdyn_field_encode_test.c"
#include "app/field_decode_test.c"
#include "tls/pskmodes_test.c"
#include "tls/preshared_test.c"
#include "tls/earlydata_test.c"
#include "transport/ackrange_process_test.c"
#include "app/dg_send_test.c"
#include "app/dg_loss_test.c"
#include "app/dg_recv_test.c"
#include "transport/losstime_test.c"
#include "transport/pnspaces_spaces_test.c"
#include "transport/pnspaces_sent_test.c"
#include "transport/pnspaces_recv_test.c"
#include "transport/protectcs_test.c"
#include "transport/shorthdr_test.c"
#include "transport/avail_test.c"
#include "transport/v2switch_test.c"
#include "transport/versdowngrade_test.c"
#include "transport/evloop_test.c"
#include "transport/connrunner_test.c"
#include "app/h3conn_establish_test.c"
#include "app/h3conn_roundtrip_test.c"
#include "app/h3reqdrive_test.c"
#include "app/h3cancel_test.c"
#include "transport/rtxstore_test.c"
#include "transport/rebuild_test.c"
#include "transport/collect_test.c"
#include "tls/kuswitch_derive_test.c"
#include "tls/kuswitch_phasebit_test.c"
#include "transport/hspto_test.c"
#include "transport/hspto_arm_test.c"
#include "transport/hspto_probe_space_test.c"
#include "app/pseudo_encode_test.c"
#include "app/header_encode_test.c"
#include "app/request_headers_test.c"
#include "crypto/fields_test.c"
#include "crypto/version_serial_test.c"
#include "crypto/sigalg_test.c"
#include "transport/rtxdrive_select_test.c"
#include "transport/rtxdrive_build_test.c"
#include "transport/rtxdrive_batch_test.c"
#include "tls/kudrive_trigger_test.c"
#include "tls/kudrive_recv_phase_test.c"
#include "tls/kudrive_discard_timing_test.c"
#include "transport/retrydrive_test.c"
#include "transport/vndrive_test.c"
#include "transport/sentmeta_test.c"
#include "transport/termgate_test.c"
#include "transport/udpsess_test.c"
#include "tls/alpnver_test.c"
#include "tls/resume_test.c"
#include "tls/ticketguard_test.c"
#include "tls/earlydrive_test.c"
#include "crypto/rfc6979_test.c"
#include "crypto/p256sign_test.c"
#include "crypto/ecdsasig_der_int_test.c"
#include "crypto/ecdsasig_sig_value_test.c"
#include "crypto/p256cert_test.c"
#include "crypto/cvecdsa_test.c"
#include "tls/eebuild_test.c"
#include "transport/crecv_collect_test.c"
#include "transport/crecv_message_test.c"
#include "tls/server_test.c"
#include "app/h3srv_test.c"
#include "app/srvwire_test.c"
#include "app/srvloop_test.c"
#include "app/priupdate_test.c"
#include "app/sendq_test.c"
#include "app/sendsess_test.c"
#include "app/srvrun_test.c"
#include "app/certreload_test.c"
#include "tls/client_wire_test.c"
#include "app/h3_loopback_test.c"
#include "app/staticfile_test.c"
#include "app/mimetype_test.c"
#include "app/h3reqenc_test.c"
#include "app/srvpin_test.c"
#include "app/srvworkers_test.c"
#include "transport/stats_test.c"
#include "app/wt_session_test.c"
#include "app/wterrmap_test.c"
#include "app/wtcapsule_test.c"
#include "app/srvworkers_migration_test.c"
#include "app/srvpoll_test.c"
#include "transport/eth_test.c"
#include "transport/xdpmac_test.c"
#include "transport/xdpbpf_test.c"
#include "transport/xskring_test.c"
#include "transport/xskumem_test.c"
#include "transport/xsksetup_test.c"
#include "transport/xdpframe_test.c"
// clang-format on

int main(void) {
  test_varint();
  test_header();
  test_dcidresolve();
  test_pnum();
  test_tparam();
  test_frame();
  test_stream();
  test_conn();
  test_sha256();
  test_hmac();
  test_hkdf();
  test_aes();
  test_gcm();
  test_chacha20();
  test_poly1305();
  test_aead();
  test_initial();
  test_hp();
  test_rtt();
  test_sent();
  test_cc();
  test_flow();
  test_udp();
  test_udp_recvfrom();
  test_udp_gso();
  test_udp_recvmmsg();
  test_rtx();
  test_ack();
  test_ncid();
  test_protect();
  test_net();
  test_x25519();
  test_handshake();
  test_schedule();
  test_endpoint();
  test_stream_ctl();
  test_connctl();
  test_dispatch();
  test_error();
  test_flowctl();
  test_abandon();
  test_ack_range();
  test_ackdelay();
  test_ackpolicy();
  test_aeadlimit();
  test_antiamp();
  test_appkeys();
  test_availfilter();
  test_base();
  test_bidi();
  test_bitset();
  test_ccloss();
  test_ccphase();
  test_cert();
  test_cidnego();
  test_cidxchg();
  test_cidpool();
  test_close_convert();
  test_closelife();
  test_coalesce();
  test_coalorder();
  test_codes();
  test_compat();
  test_compatnego();
  test_connect();
  test_contentlen();
  test_critical();
  test_crypto_offset();
  test_cwndcheck();
  test_datagram();
  test_demux();
  test_conntable();
  test_bbr();
  test_cubic();
  test_hystart();
  test_dgcc();
  test_dgcheck();
  test_dgsize();
  test_dosmitigate();
  test_downgrade();
  test_draining();
  test_dual_flow();
  test_early();
  test_ecn();
  test_ed25519();
  test_encext_check();
  test_errclass();
  test_fieldline();
  test_fieldsize();
  test_finalsize();
  test_finished();
  test_firstframe();
  test_flowobs();
  test_frame_permit();
  test_goaway_check();
  test_grease();
  test_h3control();
  test_h3dgram();
  test_h3frame();
  test_h3grease();
  test_h3stream_type();
  test_headercase();
  test_hp_chacha();
  test_hpapply();
  test_hpsample();
  test_hsdone();
  test_idlefloor();
  test_idletimeout();
  test_inflight();
  test_initiate();
  test_inittoken();
  test_insertcount();
  test_keydiscard();
  test_keyphase();
  test_keyupdate();
  test_kuderive();
  test_largestacked();
  test_linkability();
  test_literal();
  test_lossdetect();
  test_losstimer();
  test_master();
  test_middlebox();
  test_migrate();
  test_msgassembly();
  test_ncid_check();
  test_observable();
  test_oldkey();
  test_pacing();
  test_pad();
  test_path();
  test_permit();
  test_persistent();
  test_pmtu();
  test_pnlen();
  test_pnspace();
  test_prefaddr();
  test_probe();
  test_pseudoheader();
  test_pto();
  test_ptoreset();
  test_ptype();
  test_packet2();
  test_pushid();
  test_qpack_instruction();
  test_qpack_prefix();
  test_qpack_settings();
  test_qpack_huffman();
  test_qpack();
  test_recvpn();
  test_relindex();
  test_reqstream();
  test_resbits();
  test_retry_tag();
  test_retry_tag_v2();
  test_retrytoken();
  test_rttinit();
  test_rttobs();
  test_rttsample();
  test_rttvalid();
  test_settings_check();
  test_settings_dup();
  test_shutdown();
  test_spin();
  test_sreset_bit();
  test_sreset();
  test_stream_bounds();
  test_stream_flow();
  test_stream_id();
  test_stream_limit();
  test_stream_role();
  test_streams();
  test_tokentype();
  test_tpblob();
  test_tpcheck();
  test_tpext();
  test_v2keys();
  test_v2types();
  test_verinfo();
  test_verselect();
  test_version();
  test_vneg();
  test_zerortt_params();
  test_zerortt_policy();
  test_zerortt_reject();
  test_priority();
  test_keepalive();
  test_reuse();
  test_sni();
  test_alpn();
  test_alpn_match();
  test_switchrule();
  test_ticketversion();
  test_ticket();
  test_newsessionticket();
  test_zerortt_dgram();
  test_session();
  test_der();
  test_derseq();
  test_derval();
  test_pem();
  test_eckey();
  test_fio();
  test_qlog();
  test_qlogevent();
  test_keylog();
  test_cliargs();
  test_addr();
  test_udptransport();
  test_rng();
  test_clock();
  test_debug();
  test_cidgen();
  test_challenge();
  test_cipher();
  test_aead_params();
  test_hp_select();
  test_ext_versions();
  test_ext_algs();
  test_ext_block();
  test_transcript();
  test_transcript_stage();
  test_hs_message();
  test_bignum();
  test_modexp();
  test_rsa_verify();
  test_sha384();
  test_sigalgoid();
  test_rsachain();
  test_p256_field();
  test_p384_field();
  test_p384_point();
  test_ecdsa_p384_verify();
  test_p384chain();
  test_p256_point();
  test_ecdsa_verify();
  test_x509();
  test_spki();
  test_validity();
  test_ext_keyshare();
  test_clienthello();
  test_serverhello();
  test_mgf1();
  test_rsa_pss();
  test_rsa_pubkey();
  test_ec_pubkey();
  test_certverify();
  test_hsdriver();
  test_txpacket();
  test_rxpacket();
  test_framewalk();
  test_keyset();
  test_promote();
  test_discard_driver();
  test_chain();
  test_basicconstraints();
  test_san();
  test_connection();
  test_dyntable();
  test_dynget();
  test_dynfind();
  test_stream_read();
  test_credit();
  test_stream_credit();
  test_h3run_control();
  test_h3run_settings_seq();
  test_h3run_goaway();
  test_retry_drive();
  test_vn_drive();
  test_aead_suite();
  test_hp_suite();
  test_keyschedule();
  test_sentpkt();
  test_ack_process();
  test_loss_detect();
  test_dispatch_state();
  test_rxloop();
  test_txloop();
  test_antiamp_gate();
  test_connloop();
  test_connio();
  test_lossdrive();
  test_lossdelay();
  test_ptobackoff();
  test_initpad();
  test_framepack();
  test_eliciting();
  test_ackgen();
  test_ackrange();
  test_ackfreq();
  test_castore();
  test_chainverify();
  test_pathvalidate();
  test_driver();
  test_crypto_stream();
  test_tlsdriver();
  test_fullhs();
  test_fullhs_policy();
  test_cert_chain();
  test_fullhs_chain();
  test_tlsdriver_sni();
  test_client();
  test_idledrive();
  test_idlenego();
  test_closesend();
  test_sresetdrive_detect();
  test_sresetdrive_tokenmap();
  test_sresetdrive_onreset();
  test_reqorder();
  test_reqbuild();
  test_respparse();
  test_flowviol();
  test_closeframe();
  test_odcid();
  test_iscid();
  test_rscid();
  test_initpkt();
  test_ed25519_sign();
  test_shbuild();
  test_sflight_encext();
  test_sflight_certmsg();
  test_sflight_certverify_build();
  test_sflight_finished_build();
  test_sdrv();
  test_selfcert();
  test_hspkt_build();
  test_onertt();
  test_srvfin_verify();
  test_srvfin_complete();
  test_srvfin_hsdone();
  test_ch_ext_finds_alpn_and_sni();
  test_ch_ext_absent_returns_zero();
  test_ch_ext_truncated_returns_zero();
  test_negotiate_selects_h3_from_clienthello();
  test_negotiate_rejects_non_h3();
  test_negotiate_h3_among_others();
  test_negotiate_truncated();
  test_negotiate_build_response();
  test_sni_extract_from_clienthello();
  test_sni_extract_truncated();
  test_sni_extract_wrong_name_type();
  test_server_tp();
  test_h3settings_control_open();
  test_h3settings_build();
  test_h3settings_build_connect_protocol();
  test_h3settings_build_h3_datagram_and_wt_enabled();
  test_h3settings_build_h3_datagram_and_wt_disabled();
  test_h3settings_control_settings();
  test_h3settings_control_settings_advertises_connect_protocol();
  test_h3settings_control_settings_advertises_wt();
  test_capsule();
  test_lhdr_build();
  test_lhdr_parse();
  test_vpn_open();
  test_stream_send();
  test_app_send();
  test_app_recv();
  test_req_frames();
  test_field_encode();
  test_resp_build();
  test_hello();
  test_certreq();
  test_cwndctl();
  test_hrr_build();
  test_hrr_detect();
  test_hrr_group();
  test_legacy_fields();
  test_maxstreams();
  test_poll();
  test_qpackdyn_insert_encode();
  test_qpackdyn_field_encode();
  test_qpackdyn_field_decode();
  test_pskmodes();
  test_preshared();
  test_earlydata();
  test_ackrange_process();
  test_dg_send_with_length();
  test_dg_send_no_length();
  test_dg_send_over_max();
  test_dg_send_unsupported();
  test_dg_send_no_room();
  test_dg_loss_notifies();
  test_dg_loss_ignores_other();
  test_dg_loss_never_retransmit();
  test_dg_recv_with_length();
  test_dg_recv_no_length();
  test_dg_recv_truncated();
  test_losstime();
  test_pnspaces_spaces();
  test_pnspaces_sent();
  test_pnspaces_recv();
  test_protectcs();
  test_shorthdr();
  test_avail();
  test_v2switch();
  test_versdowngrade();
  test_evloop();
  test_connrunner();
  test_h3conn_establish();
  test_h3conn_roundtrip();
  test_h3reqdrive();
  test_h3cancel();
  test_rtxstore();
  test_rebuild();
  test_collect();
  test_kuswitch_derive();
  test_kuswitch_phasebit();
  test_hspto();
  test_hspto_arm();
  test_hspto_probe_space();
  test_pseudo_encode();
  test_header_encode();
  test_request_headers();
  test_fields();
  test_version_serial();
  test_sigalg();
  test_rtxdrive_select();
  test_rtxdrive_build();
  test_rtxdrive_batch();
  test_kudrive_trigger();
  test_kudrive_recv_phase();
  test_kudrive_discard_timing();
  test_retrydrive();
  test_vndrive();
  test_sentmeta();
  test_termgate();
  test_udpsess();
  test_alpnver();
  test_resume();
  test_ticketguard();
  test_earlydrive();
  test_rfc6979();
  test_p256sign();
  test_ecdsasig_der_int();
  test_ecdsasig_sig_value();
  test_p256cert();
  test_cvecdsa();
  test_eebuild();
  test_crecv_collect();
  test_crecv_message();
  test_server();
  test_h3srv();
  test_srvwire();
  test_srvloop();
  test_priupdate();
  test_sendq();
  test_sendsess();
  test_srvrun();
  test_certreload();
  test_client_wire();
  test_h3_loopback();
  test_staticfile();
  test_mimetype();
  test_h3reqenc();
  test_stats();
  test_srvpin();
  test_srvworkers();
  test_wt_session();
  test_wterrmap();
  test_wtcapsule();
  test_srvworkers_migration();
  test_srvpoll();
  test_eth();
  test_xdpmac();
  test_xdpbpf();
  test_xskring();
  test_xskumem();
  test_xsksetup();
  test_xdpframe();
  return TEST_REPORT();
}
