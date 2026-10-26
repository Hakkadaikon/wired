#include "tls/handshake/core/sdrv/sdrv_impl.h"

static int sdrv_ch_ext_one(
    const sdrv_ch_block* blk, usz* q, unsigned want_type, wired_span* ext);

/* The message is a well-framed ClientHello; sets *body_len. */
int sdrv_is_client_hello(const u8* buf, usz n, usz* body_len) {
  u8 type;
  return hs_parse(wired_span_of(buf, n), &type, body_len) == 4 &&
         type == HS_CLIENT_HELLO;
}

/* Locate the ClientHello's extensions list within body (a real, already
 * length-validated ClientHello body, per hs_parse): sets *start to just
 * past the 2-byte extensions-length field and *end to where the list
 * actually ends. The extensions-length field is self-reported by the peer,
 * so *end is clamped to body -- a claimed length that would run past the
 * real body is a malformed ClientHello and fails closed (0) here, rather
 * than handing an out-of-bounds *end to the walkers below. */
int sdrv_ch_exts_span(const u8* b, usz body, usz* start, usz* end) {
  usz exts = sdrv_ch_prefix(b, body);
  usz blen;
  if (exts == 0) {
    return 0;
  }
  blen   = (usz)b[exts] << 8 | b[exts + 1];
  *start = exts + 2;
  *end   = *start + blen;
  return *end <= body;
}

/* Take the client's want_group key_share from a ClientHello (header
 * included). */
int sdrv_take_client_keyshare(
    const u8* ch, usz ch_len, u16 want_group, u8 pub[65]) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) {
    return 0;
  }
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) {
    return 0;
  }
  return sdrv_ch_walk(ch + 4, start, end, want_group, pub);
}

/* One extension at *q: -1 overrun, 1 if it names want_type (*ext set to its
 * full TLV, header included), 0 skip; *q advances. */
static int sdrv_ch_ext_one(
    const sdrv_ch_block* blk, usz* q, unsigned want_type, wired_span* ext) {
  unsigned type;
  usz      dlen, start = *q;
  if (!sdrv_ch_hdr(blk, q, &type, &dlen)) {
    return -1;
  }
  if (type != want_type) {
    return 0;
  }
  *ext = wired_span_of(blk->b + start, 4 + dlen);
  return 1;
}

/* Walk the same extension list as sdrv_ch_walk for one extension_type,
 * independently of the key_share scan -- a small dedicated walk rather than
 * folding unrelated searches into one function, to keep CCN low. Shared by
 * the quic_transport_parameters (RFC 9001 8.2, 0x39) and pre_shared_key
 * (RFC 8446 4.2.11, 0x0029) lookups below. */
int sdrv_ch_find_ext(
    const u8* b, usz q, usz end, unsigned want_type, wired_span* ext) {
  sdrv_ch_block blk = {b, end};
  int           r   = 0;
  while (r == 0 && q + 4 <= end) {
    r = sdrv_ch_ext_one(&blk, &q, want_type, ext);
  }
  return r == 1;
}

/* Find the ClientHello's quic_transport_parameters extension_data (the raw
 * TLV, header included, as tpext_decode expects). Returns 1 and sets
 * *ext on success, 0 if the ClientHello is malformed or carries no such
 * extension. */
int sdrv_find_client_tp_ext(const u8* ch, usz ch_len, wired_span* ext) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) {
    return 0;
  }
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) {
    return 0;
  }
  return sdrv_ch_find_ext(ch + 4, start, end, TPEXT_TYPE, ext);
}

int sdrv_find_client_psk_ext(const u8* ch, usz ch_len, wired_span* ext) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) {
    return 0;
  }
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) {
    return 0;
  }
  return sdrv_ch_find_ext(ch + 4, start, end, SDRV_PSK_EXT_TYPE, ext);
}

/* Locate any extension_type in the ClientHello by its raw code point (the
 * general form of sdrv_find_client_tp_ext/sdrv_find_client_psk_ext above, for
 * guards that check several unrelated extension types). Returns 1 and sets *ext
 * (header included) on success, 0 if the ClientHello is malformed or the
 * type is absent. */
int sdrv_find_client_ext(
    const u8* ch, usz ch_len, unsigned want_type, wired_span* ext) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) {
    return 0;
  }
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) {
    return 0;
  }
  return sdrv_ch_find_ext(ch + 4, start, end, want_type, ext);
}

/* RFC 9221 3: extract the peer's advertised max_datagram_frame_size from the
 * ClientHello's transport parameters, if present. Leaves *out at 0 (absent /
 * unsupported) when the extension or the specific parameter is missing --
 * this is an optional parameter, never a ClientHello rejection. */
void sdrv_take_peer_max_datagram_frame_size(
    const u8* ch, usz ch_len, u64* out) {
  wired_span ext, tp;
  stp_out    out_v = {out, 0};
  *out             = 0;
  if (!sdrv_find_client_tp_ext(ch, ch_len, &ext)) {
    return;
  }
  if (tpext_decode(ext, &tp) == 0) {
    return;
  }
  stp_parse(tp, TP_MAX_DATAGRAM_FRAME_SIZE, &out_v);
}

/* RFC 9000 4.1/18.2: extract one integer-valued transport parameter (param_id)
 * from the ClientHello's transport parameters, if present. Leaves *out at 0
 * (absent) when the extension or the specific parameter is missing -- both
 * initial_max_data and initial_max_stream_data_bidi_local default to "send
 * nothing" when unadvertised, matching this SDK's existing absent-parameter
 * convention (sdrv_take_peer_max_datagram_frame_size above). */
void sdrv_take_peer_tp_int(const u8* ch, usz ch_len, u64 param_id, u64* out) {
  wired_span ext, tp;
  stp_out    out_v = {out, 0};
  *out             = 0;
  if (!sdrv_find_client_tp_ext(ch, ch_len, &ext)) {
    return;
  }
  if (tpext_decode(ext, &tp) == 0) {
    return;
  }
  stp_parse(tp, param_id, &out_v);
}

/* The ClientHello's decoded transport-parameter sequence in *tp; 0 if the
 * extension is missing or malformed. */
static int sdrv_client_tp(const u8* ch, usz ch_len, wired_span* tp) {
  wired_span ext;
  if (!sdrv_find_client_tp_ext(ch, ch_len, &ext)) {
    return 0;
  }
  return tpext_decode(ext, tp) != 0;
}

/* RFC 9000 18.2: 1 + the integer transport parameter param_id from the
 * ClientHello, or 0 when it is absent -- for parameters whose absence means
 * a non-zero default (ack_delay_exponent, max_ack_delay), so an explicit 0
 * stays distinguishable. */
u64 sdrv_peer_tp_plus1(const u8* ch, usz ch_len, u64 param_id) {
  wired_span tp;
  u64        v     = 0;
  stp_out    out_v = {&v, 0};
  if (!sdrv_client_tp(ch, ch_len, &tp)) {
    return 0;
  }
  return stp_parse(tp, param_id, &out_v) ? v + 1 : 0;
}

/* The legacy_session_id at body offset 34 is fully framed in ch_msg: the length
 * byte is present, is <=32, and its bytes all lie within ch_msg. */
int sdrv_sid_fits(const u8* ch_msg, usz ch_len) {
  return ch_len >= 4 + 35 && ch_msg[4 + 34] <= 32 &&
         ch_len >= 4 + 35 + (usz)ch_msg[4 + 34];
}

/* RFC 9001 8.4: QUIC runs TLS 1.3 over QUIC framing rather than TLS
 * record framing, so a compliant client's ClientHello always carries an
 * empty legacy_session_id; a non-empty one is a connection error of type
 * PROTOCOL_VIOLATION. Sets s->last_error and returns 0 on that rejection. */
int sdrv_reject_nonempty_sid(sdrv* s, u8 len) {
  if (len == 0) {
    return 1;
  }
  s->last_error = ERR_PROTOCOL_VIOLATION;
  return 0;
}
