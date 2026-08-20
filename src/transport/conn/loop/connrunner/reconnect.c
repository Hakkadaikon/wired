#include "transport/conn/loop/connrunner/reconnect.h"

#include "common/bytes/util/bytes.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/handshake/core/handshake_drive/retry_drive.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/conn/cid/retrydrive/accept.h"
#include "transport/conn/cid/retrydrive/token.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/packet/header/packet/vneg.h"
#include "transport/version/version/version.h"
#include "transport/version/vndrive/accept.h"
#include "transport/version/vndrive/reconnect.h"
#include "transport/version/vndrive/select.h"

void connrunner_reconnect_init(connrunner* r) {
  r->retry.received     = 0;
  r->retry.key_rederive = 0;
  r->retry.token_len    = 0;
  r->retry.dcid_len     = 0;
  /* RFC 9000 6.2 / RFC 9369 3.3.2: until a VN reconnect overrides it, the
   * client's Initial is sent under v1 -- key updates derive with v1 labels. */
  r->sent_version   = VERSION_1;
  r->vn_retry_count = 0;
}

/* RFC 9000 17.2.5.2: the handshake must not have progressed and the Retry
 * (first, valid tag) must be accepted; the compound lives here. */
static int retry_ok(const connrunner* r, int tag_valid) {
  return !r->io.loop.handshake_complete &&
         retrydrive_accept(r->retry.received, tag_valid);
}

int connrunner_recv_retry(connrunner* r, const retry_event* e) {
  if (!retry_ok(r, e->tag_valid)) return 0;
  return retrydrive_apply(e->token, e->scid, &r->retry);
}

/* RFC 9001 5.2: install the new Initial keys derived from the Retry DCID and
 * adopt that DCID for subsequent Initials. */
static void rederive_initial(connrunner* r) {
  initial_keys k;
  usz          off = 0;
  initial_derive(
      wired_span_of(r->retry.dcid, r->retry.dcid_len), r->io.loop.is_server,
      VERSION_1, &k);
  keyset_install(&r->io.loop.keys, LEVEL_INITIAL, &k);
  bytes_put(
      wired_mspan_of(r->io.dcid, sizeof r->io.dcid), &off,
      wired_span_of(r->retry.dcid, r->retry.dcid_len));
  r->io.dcid_len = r->retry.dcid_len;
}

int connrunner_retry_rederive(connrunner* r) {
  if (!r->retry.key_rederive) return 0;
  rederive_initial(r);
  r->retry.key_rederive = 0; /* RFC 9001 5.2: keys now match the new DCID */
  return 1;
}

void connrunner_initial_token(const connrunner* r, const u8** token, usz* len) {
  retrydrive_initial_token(&r->retry, token, len);
}

/* RFC 9000 6.2: a VN is processed only before the handshake progresses and when
 * it is not a downgrade (sent version absent from the offered list). */
static int vn_ok(const connrunner* r, const u32* offered, usz n_off) {
  return !r->io.loop.handshake_complete &&
         vndrive_accept(
             r->io.loop.handshake_complete, r->sent_version,
             verlist_of(offered, n_off));
}

/* RFC 9000 6.2: with a common version chosen, reconnect once within budget;
 * returns 1 (count incremented) or 0 when the single VN retry is spent. */
static int vn_reconnect(connrunner* r, u32 chosen) {
  if (!vndrive_should_retry(chosen, r->vn_retry_count)) return 0;
  r->vn_retry_count++;
  return 1;
}

int connrunner_recv_vn(connrunner* r, const vn_lists* l, u32* chosen) {
  if (!vn_ok(r, l->offered.list, l->offered.n)) return 0; /* downgrade/late */
  if (!vndrive_select(l->offered, l->supported, chosen))
    return CONNRUNNER_VN_ABORT; /* RFC 9000 6.2: no common version */
  return vn_reconnect(r, *chosen);
}

/* RFC 9000 6.2: the client's supported versions in preference order. */
static const u32 g_supported[2] = {VERSION_2, VERSION_1};

/* Read the i-th offered version (4 big-endian bytes) from a VN list view. */
static u32 vn_version_at(const u8* versions, usz i) {
  const u8* p = versions + i * 4;
  return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

/* Copy up to VERS_OFFERED offered versions out of the parsed VN view. */
#define VERS_OFFERED 16
static usz vn_offered(const vneg_packet* v, u32* out) {
  usz n = v->count < VERS_OFFERED ? v->count : VERS_OFFERED;
  for (usz i = 0; i < n; i++) out[i] = vn_version_at(v->versions, i);
  return n;
}

/* RFC 9000 6.2: parse a Version Negotiation packet and drive recv_vn over its
 * offered list; a malformed packet is consumed (1) without action. */
static int drive_vn(connrunner* r, const u8* pkt, usz len) {
  vneg_packet v;
  u32         offered[VERS_OFFERED], chosen;
  vn_lists    l;
  if (vneg_parse(pkt, len, &v) == 0) return 1;
  l.offered   = verlist_of(offered, vn_offered(&v, offered));
  l.supported = verlist_of(g_supported, 2);
  connrunner_recv_vn(r, &l, &chosen);
  return 1;
}

/* RFC 9000 17.2.5: parse and verify a Retry against the current DCID, then
 * drive recv_retry; a malformed Retry is consumed (1) without action. */
static int drive_retry(connrunner* r, const u8* pkt, usz len) {
  u8                token[256], dcid[WIRED_MAX_CID_LEN];
  u8                dlen;
  retry_event       e;
  wired_obuf        tok_ob = obuf_of(token, sizeof(token));
  retry_process_out out    = {&tok_ob, dcid, &dlen};
  e.tag_valid              = retry_process(
      wired_span_of(pkt, len), wired_span_of(r->io.dcid, r->io.dcid_len), &out);
  e.scid  = wired_span_of(dcid, dlen);
  e.token = wired_span_of(token, tok_ob.len);
  connrunner_recv_retry(r, &e);
  return 1;
}

/* RFC 8999 5.1: a Version field of 0 marks a Version Negotiation packet. */
static int vneg_version_zero(const u8* pkt) {
  return (pkt[1] | pkt[2] | pkt[3] | pkt[4]) == 0;
}

static int is_vneg(const u8* pkt, usz len) {
  return len >= 5 && vneg_version_zero(pkt);
}

/* Route a long-header packet that is a Retry or VN; 0 if it is neither. */
static int drive_long(connrunner* r, const u8* pkt, usz len) {
  if (is_vneg(pkt, len)) return drive_vn(r, pkt, len);
  if (packet_long_type(pkt[0], VERSION_1) == PT_RETRY)
    return drive_retry(r, pkt, len);
  return 0;
}

int connrunner_recv_reconnect(connrunner* r, const u8* pkt, usz len) {
  if (!packet_is_long(pkt[0])) return 0;
  return drive_long(r, pkt, len);
}
