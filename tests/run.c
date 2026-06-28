#include "test.h"
#include "shbuild/shbuild.c"
#include "sflight/encext.c"
#include "sflight/certmsg.c"
#include "sflight/certverify_build.c"
#include "sflight/finished_build.c"
#include "initpkt/initkeys.c"
#include "initpkt/initpkt.c"
#include "initpkt/initopen.c"
#include "idledrive/idledrive.c"
#include "idledrive/idlenego.c"
#include "idledrive/closesend.c"
#include "sresetdrive/detect.c"
#include "sresetdrive/tokenmap.c"
#include "sresetdrive/onreset.c"
#include "h3req/reqorder.c"
#include "h3req/reqbuild.c"
#include "h3req/respparse.c"
#include "flowviol/flowviol.c"
#include "flowviol/closeframe.c"
#include "tpverify/odcid.c"
#include "tpverify/iscid.c"
#include "tpverify/rscid.c"
#include "fullhs/fullhs.c"
#include "tlsdriver/tlsdriver.c"
#include "crypto_stream/crypto_tx.c"
#include "crypto_stream/crypto_rx.c"
#include "crypto_stream/ecdhe.c"
#include "h3run/control.c"
#include "h3run/settings_seq.c"
#include "h3run/goaway.c"
#include "handshake_drive/retry_drive.c"
#include "handshake_drive/vn_drive.c"
#include "protect_suite/aead_suite.c"
#include "protect_suite/hp_suite.c"
#include "schedule_drive/keyschedule.c"
#include "sentpkt/sentpkt.c"
#include "sentpkt/ack_process.c"
#include "sentpkt/loss_detect.c"
#include "keys/discard_driver.c"
#include "keys/promote.c"
#include "keys/keyset.c"
#include "pipeline/framewalk.c"
#include "pipeline/rxpacket.c"
#include "pipeline/txpacket.c"
#include "tls/hsdriver.c"
#include "tls/certverify.c"
#include "x509/ec_pubkey.c"
#include "x509/rsa_pubkey.c"
#include "rsa/rsa_pss_verify.c"
#include "rsa/pss.c"
#include "rsa/mgf1.c"
#include "tls/serverhello.c"
#include "tls/clienthello.c"
#include "tls/ext_keyshare.c"
#include "x509/validity.c"
#include "x509/spki.c"
#include "x509/x509.c"
#include "p256/ecdsa_verify.c"
#include "p256/p256_point.c"
#include "p256/p256_field.c"
#include "rsa/rsa_verify.c"
#include "bignum/modexp.c"
#include "bignum/bignum.c"
#include "tls/hs_message.c"
#include "tls/transcript_stage.c"
#include "tls/transcript.c"
#include "tls/ext_block.c"
#include "tls/ext_algs.c"
#include "tls/ext_versions.c"
#include "tls/hp_select.c"
#include "tls/aead_params.c"
#include "tls/cipher.c"
#include "rng/challenge.c"
#include "rng/cidgen.c"
#include "rng/rng.c"
#include "io/udptransport.c"
#include "io/addr.c"
#include "asn1/derval.c"
#include "asn1/derseq.c"
#include "asn1/der.c"
#include "session/session.c"
#include "datagram/zerortt_dgram.c"
#include "tls/ticketversion.c"
#include "version/switchrule.c"
#include "tls/alpn_match.c"
#include "tls/alpn.c"
#include "tls/sni.c"
#include "h3/reuse.c"
#include "closelife/keepalive.c"
#include "h3/priority.c"
#include "hash/sha512.c"
#include "qpack/base.c"
#include "qpack/fieldline.c"
#include "qpack/insertcount.c"
#include "qpack/literal.c"
#include "qpack/relindex.c"
#include "aes/aes.c"
#include "cc/cc.c"
#include "cc/ccloss.c"
#include "cc/ccphase.c"
#include "cc/cwndcheck.c"
#include "cc/ecn.c"
#include "cc/pacing.c"
#include "cc/persistent.c"
#include "chacha/aead.c"
#include "chacha/chacha20.c"
#include "chacha/poly1305.c"
#include "cid/cidpool.c"
#include "closelife/closelife.c"
#include "closelife/draining.c"
#include "closelife/idlefloor.c"
#include "closelife/idletimeout.c"
#include "conn/cidnego.c"
#include "conn/conn.c"
#include "conn/demux.c"
#include "conn/pnspace.c"
#include "datagram/datagram.c"
#include "datagram/dgcc.c"
#include "datagram/dgcheck.c"
#include "datagram/dgsize.c"
#include "ed25519/ed25519.c"
#include "endpoint/endpoint.c"
#include "error/codes.c"
#include "error/error.c"
#include "flow/dual_flow.c"
#include "flow/finalsize.c"
#include "flow/flow.c"
#include "flow/reassemble.c"
#include "flow/stream_flow.c"
#include "flow/streams.c"
#include "frame/ack.c"
#include "frame/ack_range.c"
#include "frame/close_convert.c"
#include "frame/connctl.c"
#include "frame/crypto_offset.c"
#include "frame/dispatch.c"
#include "frame/flowctl.c"
#include "frame/frame.c"
#include "frame/ncid.c"
#include "frame/ncid_check.c"
#include "frame/permit.c"
#include "frame/stream_bounds.c"
#include "frame/stream_ctl.c"
#include "fsm/fsm.c"
#include "gcm/gcm.c"
#include "grease/bitset.c"
#include "grease/early.c"
#include "grease/grease.c"
#include "grease/sreset_bit.c"
#include "h3/connect.c"
#include "h3/contentlen.c"
#include "h3/control.c"
#include "h3/critical.c"
#include "h3/errclass.c"
#include "h3/fieldsize.c"
#include "h3/firstframe.c"
#include "h3/frame.c"
#include "h3/frame_permit.c"
#include "h3/goaway_check.c"
#include "h3/grease.c"
#include "h3/h3dgram.c"
#include "h3/headercase.c"
#include "h3/pseudoheader.c"
#include "h3/pushid.c"
#include "h3/qpack_settings.c"
#include "h3/reqstream.c"
#include "h3/settings_check.c"
#include "h3/settings_dup.c"
#include "h3/shutdown.c"
#include "h3/stream_type.c"
#include "hash/hmac.c"
#include "hash/sha256.c"
#include "hkdf/hkdf.c"
#include "hp/hp.c"
#include "hp/hp_chacha.c"
#include "hp/hpapply.c"
#include "hp/hpsample.c"
#include "io/retransmit.c"
#include "io/udp.c"
#include "keyupdate/aeadlimit.c"
#include "keyupdate/initiate.c"
#include "keyupdate/keyphase.c"
#include "keyupdate/keyupdate.c"
#include "keyupdate/kuderive.c"
#include "keyupdate/oldkey.c"
#include "manage/dosmitigate.c"
#include "manage/flowobs.c"
#include "manage/linkability.c"
#include "manage/middlebox.c"
#include "manage/observable.c"
#include "manage/rttobs.c"
#include "manage/zerortt_policy.c"
#include "migrate/migrate.c"
#include "net/checksum.c"
#include "net/ipv4.c"
#include "net/memlink.c"
#include "net/udp4.c"
#include "packet/coalesce.c"
#include "packet/coalorder.c"
#include "packet/header.c"
#include "packet/inittoken.c"
#include "packet/pad.c"
#include "packet/pnlen.c"
#include "packet/pnum.c"
#include "packet/ptype.c"
#include "packet/resbits.c"
#include "packet/retry.c"
#include "packet/short.c"
#include "packet/vneg.c"
#include "path/antiamp.c"
#include "path/path.c"
#include "path/prefaddr.c"
#include "pmtu/pmtu.c"
#include "protect/protect.c"
#include "qpack/instruction.c"
#include "qpack/integer.c"
#include "qpack/prefix.c"
#include "qpack/static_table.c"
#include "qpack/string.c"
#include "recovery/ackdelay.c"
#include "recovery/ackpolicy.c"
#include "recovery/inflight.c"
#include "recovery/largestacked.c"
#include "recovery/lossdetect.c"
#include "recovery/losstimer.c"
#include "recovery/probe.c"
#include "recovery/pto.c"
#include "recovery/ptoreset.c"
#include "recovery/rtt.c"
#include "recovery/rttinit.c"
#include "recovery/rttsample.c"
#include "recovery/rttvalid.c"
#include "recovery/sent.c"
#include "recvpn/recvpn.c"
#include "retrytoken/retrytoken.c"
#include "retrytoken/tokentype.c"
#include "spin/spin.c"
#include "sreset/sreset.c"
#include "stream/bidi.c"
#include "stream/stream.c"
#include "stream/stream_id.c"
#include "stream/stream_limit.c"
#include "stream/stream_role.c"
#include "tls/appkeys.c"
#include "tls/cert.c"
#include "tls/encext_check.c"
#include "tls/finished.c"
#include "tls/handshake.c"
#include "tls/hsdone.c"
#include "tls/initial.c"
#include "tls/keydiscard.c"
#include "tls/master.c"
#include "tls/msgassembly.c"
#include "tls/retry_tag.c"
#include "tls/retry_tag_v2.c"
#include "tls/schedule.c"
#include "tls/tpext.c"
#include "tls/x25519.c"
#include "tls/zerortt_params.c"
#include "tls/zerortt_reject.c"
#include "tparam/tparam.c"
#include "tparam/tpblob.c"
#include "tparam/tpcheck.c"
#include "varint/varint.c"
#include "version/abandon.c"
#include "version/availfilter.c"
#include "version/compat.c"
#include "version/compatnego.c"
#include "version/downgrade.c"
#include "version/v2keys.c"
#include "version/v2types.c"
#include "version/verinfo.c"
#include "version/verselect.c"
#include "version/version.c"
#include "version/vneg.c"
#include "x509/chain.c"
#include "x509/basicconstraints.c"
#include "x509/san.c"
#include "connection/connection.c"
#include "qpack/dyntable.c"
#include "qpack/dynget.c"
#include "qpack/dynfind.c"
#include "flow/stream_read.c"
#include "flow/credit.c"
#include "flow/stream_credit.c"
#include "framedispatch/dispatch_state.c"
#include "udploop/rxloop.c"
#include "udploop/txloop.c"
#include "udploop/antiamp_gate.c"
#include "connloop/connloop.c"
#include "connio/connio.c"
#include "lossdrive/lossdrive.c"
#include "lossdrive/lossdelay.c"
#include "lossdrive/ptobackoff.c"
#include "pktbuild/initpad.c"
#include "pktbuild/framepack.c"
#include "pktbuild/eliciting.c"
#include "ackgen/ackgen.c"
#include "ackgen/ackrange.c"
#include "ackgen/ackfreq.c"
#include "castore/castore.c"
#include "castore/chainverify.c"
#include "castore/pathvalidate.c"
#include "driver/driver.c"
#include "client/client.c"
#include "sdrv/sdrv.c"
#include "selfcert/derenc.c"
#include "selfcert/tbs.c"
#include "selfcert/selfcert.c"
#include "hspkt/hspkt_build.c"
#include "hspkt/hspkt_open.c"
#include "hspkt/onertt.c"
#include "hspkt/unprotect.c"
#include "srvfin/verify.c"
#include "srvfin/complete.c"
#include "srvfin/hsdone.c"
#include "salpn/ch_ext.c"
#include "salpn/negotiate.c"
#include "salpn/sni_extract.c"
#include "stp/server_tp.c"
#include "stp/parse_tp.c"
#include "h3settings/control_open.c"
#include "h3settings/settings_build.c"
#include "h3settings/control_settings.c"
#include "varint_test.c"
#include "header_test.c"
#include "pnum_test.c"
#include "tparam_test.c"
#include "frame_test.c"
#include "stream_test.c"
#include "conn_test.c"
#include "sha256_test.c"
#include "hmac_test.c"
#include "hkdf_test.c"
#include "aes_test.c"
#include "gcm_test.c"
#include "chacha20_test.c"
#include "poly1305_test.c"
#include "aead_test.c"
#include "initial_test.c"
#include "hp_test.c"
#include "rtt_test.c"
#include "sent_test.c"
#include "cc_test.c"
#include "flow_test.c"
#include "udp_test.c"
#include "udp_recvfrom_test.c"
#include "retransmit_test.c"
#include "ack_test.c"
#include "ncid_test.c"
#include "protect_test.c"
#include "net_test.c"
#include "x25519_test.c"
#include "handshake_test.c"
#include "schedule_test.c"
#include "endpoint_test.c"
#include "stream_ctl_test.c"
#include "connctl_test.c"
#include "dispatch_test.c"
#include "error_test.c"
#include "packet2_test.c"
#include "flowctl_test.c"
#include "abandon_test.c"
#include "ack_range_test.c"
#include "ackdelay_test.c"
#include "ackpolicy_test.c"
#include "aeadlimit_test.c"
#include "antiamp_test.c"
#include "appkeys_test.c"
#include "availfilter_test.c"
#include "base_test.c"
#include "bidi_test.c"
#include "bitset_test.c"
#include "ccloss_test.c"
#include "ccphase_test.c"
#include "cert_test.c"
#include "cidnego_test.c"
#include "cidpool_test.c"
#include "close_convert_test.c"
#include "closelife_test.c"
#include "coalesce_test.c"
#include "coalorder_test.c"
#include "codes_test.c"
#include "compat_test.c"
#include "compatnego_test.c"
#include "connect_test.c"
#include "contentlen_test.c"
#include "critical_test.c"
#include "crypto_offset_test.c"
#include "cwndcheck_test.c"
#include "datagram_test.c"
#include "demux_test.c"
#include "dgcc_test.c"
#include "dgcheck_test.c"
#include "dgsize_test.c"
#include "dosmitigate_test.c"
#include "downgrade_test.c"
#include "draining_test.c"
#include "dual_flow_test.c"
#include "early_test.c"
#include "ecn_test.c"
#include "ed25519_test.c"
#include "encext_check_test.c"
#include "errclass_test.c"
#include "fieldline_test.c"
#include "fieldsize_test.c"
#include "finalsize_test.c"
#include "finished_test.c"
#include "firstframe_test.c"
#include "flowobs_test.c"
#include "frame_permit_test.c"
#include "goaway_check_test.c"
#include "grease_test.c"
#include "h3control_test.c"
#include "h3dgram_test.c"
#include "h3frame_test.c"
#include "h3grease_test.c"
#include "h3stream_type_test.c"
#include "headercase_test.c"
#include "hp_chacha_test.c"
#include "hpapply_test.c"
#include "hpsample_test.c"
#include "hsdone_test.c"
#include "idlefloor_test.c"
#include "idletimeout_test.c"
#include "inflight_test.c"
#include "initiate_test.c"
#include "inittoken_test.c"
#include "insertcount_test.c"
#include "keydiscard_test.c"
#include "keyphase_test.c"
#include "keyupdate_test.c"
#include "kuderive_test.c"
#include "largestacked_test.c"
#include "linkability_test.c"
#include "literal_test.c"
#include "lossdetect_test.c"
#include "losstimer_test.c"
#include "master_test.c"
#include "middlebox_test.c"
#include "migrate_test.c"
#include "msgassembly_test.c"
#include "ncid_check_test.c"
#include "observable_test.c"
#include "oldkey_test.c"
#include "pacing_test.c"
#include "pad_test.c"
#include "path_test.c"
#include "permit_test.c"
#include "persistent_test.c"
#include "pmtu_test.c"
#include "pnlen_test.c"
#include "pnspace_test.c"
#include "prefaddr_test.c"
#include "probe_test.c"
#include "pseudoheader_test.c"
#include "pto_test.c"
#include "ptoreset_test.c"
#include "ptype_test.c"
#include "pushid_test.c"
#include "qpack_instruction_test.c"
#include "qpack_prefix_test.c"
#include "qpack_settings_test.c"
#include "qpack_test.c"
#include "recvpn_test.c"
#include "relindex_test.c"
#include "reqstream_test.c"
#include "resbits_test.c"
#include "retry_tag_test.c"
#include "retry_tag_v2_test.c"
#include "retrytoken_test.c"
#include "rttinit_test.c"
#include "rttobs_test.c"
#include "rttsample_test.c"
#include "rttvalid_test.c"
#include "settings_check_test.c"
#include "settings_dup_test.c"
#include "shutdown_test.c"
#include "spin_test.c"
#include "sreset_bit_test.c"
#include "sreset_test.c"
#include "stream_bounds_test.c"
#include "stream_flow_test.c"
#include "stream_id_test.c"
#include "stream_limit_test.c"
#include "stream_role_test.c"
#include "streams_test.c"
#include "tokentype_test.c"
#include "tpblob_test.c"
#include "tpcheck_test.c"
#include "tpext_test.c"
#include "v2keys_test.c"
#include "v2types_test.c"
#include "verinfo_test.c"
#include "verselect_test.c"
#include "version_test.c"
#include "vneg_test.c"
#include "zerortt_params_test.c"
#include "zerortt_policy_test.c"
#include "zerortt_reject_test.c"
#include "priority_test.c"
#include "keepalive_test.c"
#include "reuse_test.c"
#include "sni_test.c"
#include "alpn_test.c"
#include "alpn_match_test.c"
#include "switchrule_test.c"
#include "ticketversion_test.c"
#include "zerortt_dgram_test.c"
#include "session_test.c"
#include "der_test.c"
#include "derseq_test.c"
#include "derval_test.c"
#include "addr_test.c"
#include "udptransport_test.c"
#include "rng_test.c"
#include "cidgen_test.c"
#include "challenge_test.c"
#include "cipher_test.c"
#include "aead_params_test.c"
#include "hp_select_test.c"
#include "ext_versions_test.c"
#include "ext_algs_test.c"
#include "ext_block_test.c"
#include "transcript_test.c"
#include "transcript_stage_test.c"
#include "hs_message_test.c"
#include "bignum_test.c"
#include "modexp_test.c"
#include "rsa_verify_test.c"
#include "p256_field_test.c"
#include "p256_point_test.c"
#include "ecdsa_verify_test.c"
#include "x509_test.c"
#include "spki_test.c"
#include "validity_test.c"
#include "ext_keyshare_test.c"
#include "clienthello_test.c"
#include "serverhello_test.c"
#include "mgf1_test.c"
#include "rsa_pss_test.c"
#include "rsa_pubkey_test.c"
#include "ec_pubkey_test.c"
#include "certverify_test.c"
#include "hsdriver_test.c"
#include "txpacket_test.c"
#include "rxpacket_test.c"
#include "framewalk_test.c"
#include "keyset_test.c"
#include "promote_test.c"
#include "discard_driver_test.c"
#include "chain_test.c"
#include "basicconstraints_test.c"
#include "san_test.c"
#include "connection_test.c"
#include "dyntable_test.c"
#include "dynget_test.c"
#include "dynfind_test.c"
#include "stream_read_test.c"
#include "credit_test.c"
#include "stream_credit_test.c"
#include "h3run_control_test.c"
#include "h3run_settings_seq_test.c"
#include "h3run_goaway_test.c"
#include "retry_drive_test.c"
#include "vn_drive_test.c"
#include "aead_suite_test.c"
#include "hp_suite_test.c"
#include "keyschedule_test.c"
#include "sentpkt_test.c"
#include "ack_process_test.c"
#include "loss_detect_test.c"
#include "dispatch_state_test.c"
#include "rxloop_test.c"
#include "txloop_test.c"
#include "antiamp_gate_test.c"
#include "connloop_test.c"
#include "connio_test.c"
#include "lossdrive_test.c"
#include "lossdelay_test.c"
#include "ptobackoff_test.c"
#include "initpad_test.c"
#include "framepack_test.c"
#include "eliciting_test.c"
#include "ackgen_test.c"
#include "ackrange_test.c"
#include "ackfreq_test.c"
#include "castore_test.c"
#include "chainverify_test.c"
#include "pathvalidate_test.c"
#include "driver_test.c"
#include "crypto_stream_test.c"
#include "tlsdriver_test.c"
#include "fullhs_test.c"
#include "client_test.c"
#include "idledrive_test.c"
#include "idlenego_test.c"
#include "closesend_test.c"
#include "sresetdrive_detect_test.c"
#include "sresetdrive_tokenmap_test.c"
#include "sresetdrive_onreset_test.c"
#include "reqorder_test.c"
#include "reqbuild_test.c"
#include "respparse_test.c"
#include "flowviol_test.c"
#include "closeframe_test.c"
#include "odcid_test.c"
#include "iscid_test.c"
#include "rscid_test.c"
#include "initpkt_test.c"
#include "ed25519_sign_test.c"
#include "shbuild_test.c"
#include "sflight_encext_test.c"
#include "sflight_certmsg_test.c"
#include "sflight_certverify_build_test.c"
#include "sflight_finished_build_test.c"
#include "sdrv_test.c"
#include "selfcert_test.c"
#include "hspkt_build_test.c"
#include "onertt_test.c"
#include "srvfin_verify_test.c"
#include "srvfin_complete_test.c"
#include "srvfin_hsdone_test.c"
#include "ch_ext_test.c"
#include "negotiate_test.c"
#include "sni_extract_test.c"
#include "server_tp_test.c"
#include "h3settings_control_open_test.c"
#include "h3settings_build_test.c"
#include "h3settings_control_settings_test.c"

int main(void)
{
    test_varint();
    test_header();
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
    test_antiamp_budget();
    test_appkeys();
    test_availfilter_grease_excluded();
    test_qpack_base_positive();
    test_bidi_closed();
    test_bitset_may_clear();
    test_ccloss_ssthresh();
    test_ccphase_in_slow_start();
    test_cert_parse();
    test_cidnego_adopt();
    test_cidpool_limit();
    test_close_needs_convert_matrix();
    test_life_idle_silent_close();
    test_coalesce_split();
    test_coalorder_long_any();
    test_codes_standard();
    test_v1_v2_compatible();
    test_compatnego();
    test_connect_ok();
    test_contentlen_match();
    test_critical_classify();
    test_crypto_offset_ok();
    test_cwnd_can_send_boundary();
    test_datagram_with_len();
    test_demux();
    test_dgcc();
    test_dgcheck();
    test_dgsize();
    test_dosmitigate();
    test_downgrade();
    test_draining_period_is_3pto();
    test_dual_flow();
    test_early_client();
    test_ecn_counts_valid();
    test_ed25519_rfc_test1();
    test_encext_check();
    test_known_block();
    test_fieldline_indexed_golden();
    test_field_section_ok();
    test_finalsize_data();
    test_finished();
    test_firstframe_control();
    test_flowobs_start();
    test_data_headers();
    test_server_bidi();
    test_grease_param();
    test_h3control_single();
    test_quarter_from_stream();
    test_h3frame_generic();
    test_h3grease();
    test_h3stream_type_parse();
    test_headercase_lower();
    test_hp_chacha();
    test_hpapply_byte0_long();
    test_hpsample_offset();
    test_hsdone();
    test_idlefloor_floor();
    test_idle_effective_min();
    test_inflight_ack_eliciting();
    test_initiate();
    test_inittoken_roundtrip();
    test_qpack_ric_zero();
    test_keydiscard();
    test_keyphase();
    test_keyupdate_phase_tracks();
    test_kuderive();
    test_largestacked_update();
    test_linkability();
    test_literal_namref_golden();
    test_loss_by_packet_boundary();
    test_losstimer();
    test_master();
    test_initial_ok();
    test_migrate_before_handshake();
    test_msgassembly();
    test_ncid_check();
    test_observable_long();
    test_oldkey();
    test_pacing_interval();
    test_pad();
    test_path_validation_match();
    test_permit_matrix();
    test_persistent_threshold();
    test_pmtu_grow();
    test_pnlen_boundaries();
    test_pnspace_starts_at_zero();
    test_prefaddr_may_migrate();
    test_probe_count();
    test_ph_classify();
    test_pto_backoff();
    test_ptoreset();
    test_ptype_each();
    test_push_init();
    test_qpack_enc_instr_roundtrip();
    test_qpack_prefix_empty();
    test_qpack_settings_value();
    test_qpack_integer_vector();
    test_recvpn_dedup();
    test_qpack_rel_to_abs();
    test_reqstream_ok_order();
    test_resbits();
    test_retry_tag_roundtrip();
    test_retry_tag_v2();
    test_retrytoken();
    test_rttinit_is_first();
    test_rttobs_edge();
    test_rttsample_min();
    test_rttvalid_sample_valid();
    test_settings_reserved();
    test_settings_dup_distinct();
    test_shutdown_processes();
    test_spin_roles();
    test_sreset_bit_any();
    test_sreset_token();
    test_stream_bounds();
    test_stream_flow_consume();
    test_stream_id_types();
    test_stream_limit();
    test_role_bidi();
    test_streams_limit();
    test_tokentype_retry();
    test_blob_token();
    test_tpcheck();
    test_tpext_roundtrip();
    test_salt_values();
    test_v2_wire_values();
    test_verinfo_roundtrip();
    test_verselect_chosen_ok();
    test_version_reserved();
    test_vneg_downgrade_checks();
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
    test_zerortt_dgram();
    test_session();
    test_der_short_form();
    test_derseq_two_ints();
    test_derval_oid_equal();
    test_addr_from_octets();
    test_transport_connect();
    test_rng_distinct_and_full();
    test_cidgen_len_bounds();
    test_challenge_distinct();
    test_cipher_supported();
    test_aead_params_key_len();
    test_hp_select_is_chacha();
    test_ext_versions_golden();
    test_ext_groups_golden();
    test_ext_block_concat();
    test_transcript_empty();
    test_transcript_stage_ch_sh();
    test_hs_message_short();
    test_bn_be_roundtrip();
    test_modexp_known();
    test_rsa_pkcs1_valid();
    test_p256_field_inv();
    test_p256_g_on_curve();
    test_ecdsa_valid();
    test_x509_parse_golden();
    test_spki_golden();
    test_validity_golden();
    test_ext_key_share_wire();
    test_client_hello_has_all_exts();
    test_server_hello_roundtrip();
    test_mgf1_kat();
    test_rsa_pss();
    test_rsa_pubkey_extract();
    test_ec_pubkey_extract();
    test_certverify_bad_scheme();
    test_server_does_not_send_before_clienthello();
    test_txpacket_roundtrip();
    test_rxpacket_payload_view();
    test_framewalk_sequence();
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
    test_h3settings_control_settings();
    return TEST_REPORT();
}
