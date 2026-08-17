#include "app/webtransport/exporter/exporter.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "tls/handshake/core/tls/exporter.h"

/* 1 iff label and app_context both fit their 8-bit length-prefixed fields
 * (draft-ietf-webtrans-http3-15 4.8). */
static int ctx_fields_fit(wired_span label, wired_span app_context) {
  return label.n <= QUIC_WT_EXPORTER_CTX_LABEL_MAX &&
         app_context.n <= QUIC_WT_EXPORTER_CTX_CONTEXT_MAX;
}

/* Append one 8-bit-length-prefixed field (label or app_context) at *off,
 * advancing *off. Returns 1 ok, 0 if out lacks capacity. */
static int put_len8_field(u8* out, usz cap, usz* off, wired_span field) {
  if (*off + 1 + field.n > cap) return 0;
  out[*off] = (u8)field.n;
  *off += 1;
  bytes_memcpy(out + *off, field.p, field.n);
  *off += field.n;
  return 1;
}

/* Append both length-prefixed fields after the 8-byte session ID prefix.
 * Returns the total serialized length, or 0 if out lacks capacity. */
static usz put_ctx_fields(
    u8* out, usz cap, wired_span label, wired_span app_context) {
  usz off = 8;
  if (!put_len8_field(out, cap, &off, label)) return 0;
  if (!put_len8_field(out, cap, &off, app_context)) return 0;
  return off;
}

usz quic_wt_exporter_ctx_encode(
    u64        session_id,
    wired_span label,
    wired_span app_context,
    u8*        out,
    usz        cap) {
  if (!ctx_fields_fit(label, app_context) || cap < 8) return 0;
  be_put_be64(out, session_id);
  return put_ctx_fields(out, cap, label, app_context);
}

/* draft-ietf-webtrans-http3-15 4.8 */
int quic_wt_exporter(
    const u8    exporter_secret[QUIC_HKDF_PRK],
    u64         session_id,
    wired_span  label,
    wired_span  app_context,
    wired_mspan okm) {
  u8  ctx[QUIC_WT_EXPORTER_CTX_MAX];
  usz ctx_len = quic_wt_exporter_ctx_encode(
      session_id, label, app_context, ctx, sizeof ctx);
  static const u8 exporter_label[] = "EXPORTER-WebTransport";
  if (!ctx_len) return 0;
  return tls_exporter(
      exporter_secret, wired_span_of(exporter_label, sizeof exporter_label - 1),
      wired_span_of(ctx, ctx_len), okm);
}
