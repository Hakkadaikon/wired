#include "app/http3/core/h3settings/control_settings.h"

#include "app/http3/core/h3/grease.h" /* quic_h3_grease_value */
#include "app/http3/core/h3settings/control_open.h"
#include "app/http3/core/h3settings/settings_build.h"
#include "common/platform/rng/rng.h" /* quic_rng_bytes */

/* RFC 9114 7.2.4.1 default: unlimited field section size is the absence of the
 * setting; we advertise concrete defaults so the peer (e.g. curl) sees them. */
#define DEFAULT_MAX_FIELD_SECTION_SIZE 0x4000 /* 16 KiB */
#define DEFAULT_QPACK_MAX_TABLE_CAP 0
#define DEFAULT_QPACK_BLOCKED_STREAMS 0
/* RFC 9220 3: srvrun's request path validates :protocol
 * (quic_h3_connect_protocol_ok, wired via srvrun_is_wt_connect) before
 * establishing a WebTransport session, so it is safe to advertise. */
#define DEFAULT_ENABLE_CONNECT_PROTOCOL 1

/* draft-ietf-webtrans-http3 8.2: sessions this server accepts per
 * connection -- srvloop serves one WebTransport session at a time. */
#define DEFAULT_WT_MAX_SESSIONS 1

/* draft-ietf-webtrans-http3-15 5.5.1/5.5.2/5.5.3 (WTH3-051): initial
 * session-level flow control limits advertised so a peer that enables flow
 * control (SS5.1) knows the starting budget rather than discovering it only
 * from a later WT_MAX_STREAMS/WT_MAX_DATA capsule. Match this SDK's own
 * static session cap (WIRED_SRVLOOP_MAX_WT_STREAMS-equivalent single-session
 * shape) rather than an arbitrary number. */
#define DEFAULT_WT_INITIAL_MAX_STREAMS_UNI 100
#define DEFAULT_WT_INITIAL_MAX_STREAMS_BIDI 100
#define DEFAULT_WT_INITIAL_MAX_DATA 0x100000 /* 1 MiB */

/* RFC 9114 7.2.4.1 / 9114-064: a receiver must ignore any SETTINGS identifier
 * it does not recognize (7.2.8), so a real HTTP/3 server sending one from
 * time to time (not on every connection) is what actually exercises a peer's
 * ignore-unknown handling rather than merely tolerating one byte-identical
 * frame forever. One random byte decides both whether to grease this
 * connection's SETTINGS (low bit) and, if so, which reserved identifier
 * (quic_h3_grease_value of the whole byte) to send. A failed RNG read skips
 * greasing -- it is a robustness exercise, never a reason to fail SETTINGS.
 */
static u64 control_settings_grease_id(void) {
  u8 b;
  if (!quic_rng_bytes(&b, 1)) return 0;
  if (b & 1) return 0;
  return quic_h3_grease_value(b);
}

/* The control-stream SETTINGS values: the defaults, plus the H3-datagram +
 * WebTransport pair when advertise_wt is set, plus an occasional grease
 * identifier (see control_settings_grease_id). */
static quic_h3settings_in control_settings_in(int advertise_wt) {
  quic_h3settings_in in = {
      DEFAULT_MAX_FIELD_SECTION_SIZE,
      DEFAULT_QPACK_MAX_TABLE_CAP,
      DEFAULT_QPACK_BLOCKED_STREAMS,
      DEFAULT_ENABLE_CONNECT_PROTOCOL,
      0,
      0,
      control_settings_grease_id(),
      0,
      0,
      0};
  if (advertise_wt) {
    in.enable_h3_datagram          = 1;
    in.wt_max_sessions             = DEFAULT_WT_MAX_SESSIONS;
    in.wt_initial_max_streams_uni  = DEFAULT_WT_INITIAL_MAX_STREAMS_UNI;
    in.wt_initial_max_streams_bidi = DEFAULT_WT_INITIAL_MAX_STREAMS_BIDI;
    in.wt_initial_max_data         = DEFAULT_WT_INITIAL_MAX_DATA;
  }
  return in;
}

/* RFC 9114 6.2.1 */
int quic_h3settings_control_stream(
    int advertise_wt, u8* out, usz cap, usz* out_len) {
  usz                pre = 0;
  quic_h3settings_in in  = control_settings_in(advertise_wt);
  quic_obuf          ob;
  if (!quic_h3settings_control_prefix(out, cap, &pre)) return 0;
  ob = quic_obuf_of(out + pre, cap - pre);
  if (!quic_h3settings_build(&in, &ob)) return 0;
  *out_len = pre + ob.len;
  return 1;
}

int quic_h3settings_h3_datagram_monotonic_ok(u64 prior_value, u64 new_value) {
  return new_value >= prior_value;
}

/* The three settings always sent (settings_build.c's unconditional trio):
 * each is a limit the client relies on, so 0-RTT compatibility requires
 * current >= prior on all three. */
static int core_limits_compatible(
    const quic_h3settings_in* prior, const quic_h3settings_in* current) {
  return current->max_field_section_size >= prior->max_field_section_size &&
         current->qpack_max_table_capacity >= prior->qpack_max_table_capacity &&
         current->qpack_blocked_streams >= prior->qpack_blocked_streams;
}

/* The three opt-in extension switches: each is conditionally sent, but the
 * same "never regress" rule applies -- a client that saw the extension
 * enabled (or a higher WT session count) must not see it withdrawn or
 * lowered. */
static int extension_limits_compatible(
    const quic_h3settings_in* prior, const quic_h3settings_in* current) {
  return current->enable_connect_protocol >= prior->enable_connect_protocol &&
         current->enable_h3_datagram >= prior->enable_h3_datagram &&
         current->wt_max_sessions >= prior->wt_max_sessions;
}

/* draft-ietf-webtrans-http3-15 5.5: the three WT flow-control initial
 * limits are, like the core limits above, values a 0-RTT client's WT
 * session(s) may already rely on -- never regress. */
static int wt_flow_limits_compatible(
    const quic_h3settings_in* prior, const quic_h3settings_in* current) {
  return current->wt_initial_max_streams_uni >=
             prior->wt_initial_max_streams_uni &&
         current->wt_initial_max_streams_bidi >=
             prior->wt_initial_max_streams_bidi &&
         current->wt_initial_max_data >= prior->wt_initial_max_data;
}

int quic_h3settings_zerortt_compatible(
    const quic_h3settings_in* prior, const quic_h3settings_in* current) {
  return core_limits_compatible(prior, current) &&
         extension_limits_compatible(prior, current) &&
         wt_flow_limits_compatible(prior, current);
}
