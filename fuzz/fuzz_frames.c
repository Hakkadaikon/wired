/* libFuzzer harness for the QUIC frame decoders (RFC 9000 19) and the
 * transport-parameter parsers (RFC 9000 18/7.3). Hosted build only —
 * mirrors tests/run.c's unity-include style, but this file itself may use
 * the standard library since it lives outside src/.
 *
 * Every frame decoder validates its own leading type varint, so the same
 * raw input is handed to each one: the fuzzer's first byte naturally
 * selects which decoder engages, and all the others exercise their
 * cheap-reject path. The same bytes then drive the transport-parameter
 * TLV walkers, whose wire format (varint id + varint length + value) is a
 * plausible reinterpretation of any frame-shaped input. */
#include <stddef.h>
#include <stdint.h>

#include "common/bytes/varint/varint.c"
#include "transport/packet/frame/frame/ack.c"
#include "transport/packet/frame/frame/ack_range.c"
#include "transport/packet/frame/frame/connctl.c"
#include "transport/packet/frame/frame/crypto_offset.c"
#include "transport/packet/frame/frame/dispatch.c"
#include "transport/packet/frame/frame/flowctl.c"
#include "transport/packet/frame/frame/frame.c"
#include "transport/packet/frame/frame/ncid.c"
#include "transport/packet/frame/frame/permit.c"
#include "transport/packet/frame/frame/stream_bounds.c"
#include "transport/packet/frame/frame/stream_ctl.c"
#include "tls/ext/stp/parse_tp.c"
#include "tls/ext/tparam/tparam.c"
#include "tls/ext/tparam/tpblob.c"
#include "tls/ext/tparam/tpcheck.c"
#include "tls/ext/tpverify/iscid.c"
#include "tls/ext/tpverify/odcid.c"
#include "tls/ext/tpverify/rscid.c"

/* Hand the same bytes to every frame decoder; each rejects a wrong type
 * varint in O(1), and the matching one parses for real. */
static void fuzz_frame_decoders(const u8 *buf, usz n) {
  crypto_frame          cf;
  stream_frame          sf;
  conn_close_frame      cc;
  ack_frame             af;
  ncid_frame            nf;
  reset_stream_frame    rs;
  stop_sending_frame    ss;
  reset_stream_at_frame ra;
  data_frame            df;
  stream_data_frame     sd;
  streams_frame         st;
  new_token_frame       nt;
  u64                   seq;
  u8                    path[PATH_DATA];

  frame_get_crypto(buf, n, &cf);
  frame_get_stream(buf, n, &sf);
  frame_get_conn_close(buf, n, &cc);
  ack_decode(buf, n, &af);
  ncid_decode(buf, n, &nf);
  reset_stream_decode(buf, n, &rs);
  stop_sending_decode(buf, n, &ss);
  reset_stream_at_decode(buf, n, &ra);
  max_data_decode(buf, n, &df);
  data_blocked_decode(buf, n, &df);
  max_stream_data_decode(buf, n, &sd);
  stream_data_blocked_decode(buf, n, &sd);
  max_streams_decode(buf, n, &st);
  streams_blocked_decode(buf, n, &st);
  new_token_decode(buf, n, &nt);
  retire_cid_decode(buf, n, &seq);
  path_decode(buf, n, FRAME_PATH_CHALLENGE, path);
  path_decode(buf, n, FRAME_PATH_RESPONSE, path);
  handshake_done_decode(buf, n);
}

/* RFC 9000 12.4: classify the leading type varint and run the per-kind
 * predicates across every packet type. */
static void fuzz_classify(const u8 *buf, usz n) {
  u64 type;
  if (!varint_decode(buf, n, &type)) return;
  frame_kind kind = frame_classify(type);
  frame_ack_eliciting(kind);
  frame_is_grease(type);
  frame_server_recv_forbidden(kind);
  for (int pkt = PKT_INITIAL; pkt <= PKT_1RTT; pkt++) {
    frame_permitted(kind, (packet_type)pkt);
  }
}

/* Reinterpret the same bytes as a transport-parameter TLV sequence. */
static void fuzz_tparams(const u8 *data, usz n) {
  wired_span tp = wired_span_of(data, n);

  u64        id, value;
  wired_span blob;
  tparam_get_int(tp, &id, &value);
  tparam_get_blob(tp, &id, &blob);
  tparam_no_duplicates(tp);

  struct preferred_address pa;
  tparam_get_preferred_address(data, n, &pa);

  /* Scan for a few ids across the whole sequence (integer and CID-valued). */
  static const u64 ids[] = {
      TP_ORIGINAL_DESTINATION_CONNECTION_ID, TP_MAX_IDLE_TIMEOUT,
      TP_INITIAL_MAX_DATA, TP_INITIAL_SOURCE_CONNECTION_ID,
      TP_RETRY_SOURCE_CONNECTION_ID};
  static const u8 cid[] = {0xc0, 0xff, 0xee, 0x00};
  wired_span      cid_span = wired_span_of(cid, sizeof(cid));
  for (usz i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
    u64        v;
    wired_span bytes;
    stp_out    out = {&v, &bytes};
    if (!stp_parse(tp, ids[i], &out)) continue;
    tparam_range_ok(ids[i], v);
    tpverify_iscid(cid_span, bytes);
    tpverify_odcid(cid_span, bytes);
    tpverify_rscid_in in = {1, cid_span, bytes, 1};
    tpverify_rscid(&in);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const u8 *buf = (const u8 *)data;
  usz       n   = (usz)size;
  if (n == 0) return 0;

  fuzz_frame_decoders(buf, n);
  fuzz_classify(buf, n);
  fuzz_tparams(buf, n);
  return 0;
}
