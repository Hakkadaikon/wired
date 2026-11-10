#include "app/webtransport/exporter/exporter.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "tls/handshake/core/tls/exporter.h"

/* 1 iff label and app_context both fit their 8-bit length-prefixed fields
 * (draft-ietf-webtrans-http3-15 4.8). */
static int ctx_fields_fit(wired_span label, wired_span app_context) {
  return label.n <= WT_EXPORTER_CTX_LABEL_MAX &&
         app_context.n <= WT_EXPORTER_CTX_CONTEXT_MAX;
}

/* Append one 8-bit-length-prefixed field (label or app_context) at *off,
 * advancing *off. */
static void put_len8_field(u8* out, usz* off, wired_span field) {
  out[*off] = (u8)field.n;
  *off += 1;
  bytes_memcpy(out + *off, field.p, field.n);
  *off += field.n;
}

/* Serialize the WebTransport Exporter Context struct (the session ID, then
 * the two length-prefixed fields) into out, sized for the largest one.
 * Returns its length, or 0 if label or app_context exceeds its field. */
static usz wt_exporter_ctx_encode(
    u64        session_id,
    wired_span label,
    wired_span app_context,
    u8         out[WT_EXPORTER_CTX_MAX]) {
  usz off = 8;
  if (!ctx_fields_fit(label, app_context)) {
    return 0;
  }
  be_put_be64(out, session_id);
  put_len8_field(out, &off, label);
  put_len8_field(out, &off, app_context);
  return off;
}

/* draft-ietf-webtrans-http3-16 4.8 */
int wt_exporter(
    u16         suite,
    const u8*   exporter_secret,
    u64         session_id,
    wired_span  label,
    wired_span  app_context,
    wired_mspan okm) {
  u8  ctx[WT_EXPORTER_CTX_MAX];
  usz ctx_len = wt_exporter_ctx_encode(session_id, label, app_context, ctx);
  static const u8 exporter_label[] = "EXPORTER-WebTransport";
  if (!ctx_len) {
    return 0;
  }
  return tls_exporter_suite(
      suite, exporter_secret,
      wired_span_of(exporter_label, sizeof exporter_label - 1),
      wired_span_of(ctx, ctx_len), okm);
}
