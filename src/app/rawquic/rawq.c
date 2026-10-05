#include "app/rawquic/rawq.h"

#include "app/http3/core/h3/frame.h"
#include "app/webtransport/errmap/errmap/errmap.h"
#include "common/bytes/varint/varint.h"

/* [raw][uni][signalled]: RFC 9000 2.1 direction bit (0x2) x the leading
 * varint matching the WT signal for that direction
 * (draft-ietf-webtrans-http3-15 4.2). On raw QUIC the signal carries no
 * meaning (draft-ietf-moq-transport-19 3.3), so both columns agree. */
static const rawq_route_kind rawq_route_tab[2][2][2] = {
    {{RAWQ_ROUTE_REQUEST_H3, RAWQ_ROUTE_WT_BIDI},
     {RAWQ_ROUTE_H3_UNI, RAWQ_ROUTE_WT_UNI}},
    {{RAWQ_ROUTE_RAW_BIDI, RAWQ_ROUTE_RAW_BIDI},
     {RAWQ_ROUTE_RAW_UNI, RAWQ_ROUTE_RAW_UNI}},
};

/* The WT signal per direction: bidi 0x41, uni 0x54. */
static const u64 rawq_signal_of[2] = {
    H3_STREAM_WEBTRANSPORT_BIDI, H3_STREAM_WEBTRANSPORT};

/* 1 if first's leading varint decodes (RFC 9000 16) and equals want. */
static int rawq_leads_with(wired_span first, u64 want) {
  u64 v;
  usz off = 0;
  if (!varint_take(first, &off, &v)) return 0;
  return v == want;
}

rawq_route_kind rawq_route(int raw, u64 stream_id, wired_span first) {
  int uni = (int)((stream_id >> 1) & 1);
  int sig = rawq_leads_with(first, rawq_signal_of[uni]);
  return rawq_route_tab[raw != 0][uni][sig];
}

u64 rawq_reset_code_out(int raw, u32 app) {
  return raw ? (u64)app : wired_wterrmap_to_http3(app);
}

/* Raw QUIC: the wire code is the MoQT code itself when it fits in u32. */
static int rawq_code_in_raw(u64 wire, u32* app) {
  if (wire > 0xffffffffull) return 0;
  *app = (u32)wire;
  return 1;
}

int rawq_reset_code_in(int raw, u64 wire, u32* app) {
  return raw ? rawq_code_in_raw(wire, app)
             : wired_wterrmap_from_http3(wire, app);
}

usz rawq_dgram_prefix_len(int raw, u64 connect_stream_id) {
  return raw ? 0 : varint_len(connect_stream_id / 4);
}

u64 rawq_uni_first_id(int raw) {
  return raw ? RAWQ_UNI_FIRST_RAW : RAWQ_UNI_FIRST_H3;
}
