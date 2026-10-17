#include "app/http3/server/srvboot/srvboot_impl.h"

static int srvboot_set_cids(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    const wired_header*       h);
static void srvboot_set_reset_token(
    const wired_srvboot_conn* conn, const wired_srvboot_id* id);
static void srvboot_init_server(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_server_init_in*     in);

/* RFC 9000 17.2 (v1) / RFC 9369 3.2 (v2): byte0 wears a long-header Initial
 * under `version`. The type-bit layout is version-dependent (v2's Initial
 * bits are a rotation of v1's), so this always needs the packet's own
 * Version field alongside byte0, never byte0 alone. */
int srvboot_is_long_initial(u8 byte0, u32 version) {
  return packet_long_type(byte0, version) == PT_INITIAL;
}

/* 1 if dg has room for a long header prefix (byte0 + 4-byte version) and
 * wears the long-header form bit. */
int srvboot_is_initial_sized(const u8* dg, usz len) {
  return len >= 6 && (dg[0] & 0x80) != 0;
}

int wired_srvboot_is_initial(const u8* dg, usz len) {
  if (!srvboot_is_initial_sized(dg, len)) {
    return 0;
  }
  if (!srvboot_is_long_initial(dg[0], be_get_be32(dg + 1))) {
    return 0;
  }
  return len >= (usz)6 + dg[5];
}

/* Init the server and its loop. The client's DCID (this Initial's DCID) is the
 * ODCID for Initial keys (RFC 9001 5.2); the client's SCID is the DCID the
 * server writes back and the loop is seeded with (RFC 9000 17.2 / 5.1). */
/* After a Retry, wire the token-recovered true ODCID (advertised as
 * original_destination_connection_id) alongside this Initial's own header
 * DCID (the key-derivation input, and the Retry's SCID advertised back as
 * retry_source_connection_id) -- three distinct RFC 9000 7.3 values that
 * must not collapse into one field (RFC 9001 5.2: reusing the true ODCID
 * for key derivation here breaks decryption of every post-Retry Initial,
 * whose keys are derived from the RETRY's SCID, not the original DCID). */
static int srvboot_set_cids(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    const wired_header*       h) {
  wired_span scid = wired_span_of(id->scid, id->scid_len);
  wired_span dcid = wired_span_of(h->dcid, h->dcid_len);
  if (!id->retry_odcid_len) {
    return wired_server_set_cids(conn->s, dcid, scid);
  }
  if (!sdrv_set_cids_retried(
          &conn->s->sdrv, dcid, scid,
          wired_span_of(id->retry_odcid, id->retry_odcid_len))) {
    return 0;
  }
  return sdrv_set_retry_scid(&conn->s->sdrv, dcid);
}

const u8* srvboot_reset_seed(const wired_srvboot_id* id) {
  return id->reset_seed ? id->reset_seed : id->cert_seed;
}

/* RFC 9000 10.3.1: advertise a stateless_reset_token for this connection's
 * server SCID, derived from the signing key's secret so the token survives
 * a server restart -- the one situation the token exists for. */
static void srvboot_set_reset_token(
    const wired_srvboot_conn* conn, const wired_srvboot_id* id) {
  u8 key[SRESET_KEY], token[SRESET_TOKEN];
  sreset_key_derive(srvboot_reset_seed(id), key);
  sreset_token(key, id->scid, id->scid_len, token);
  wired_server_set_reset_token(conn->s, token);
}

/* RFC 8446 4.6.1 with key rotation: id->ticket_key is the seed; this
 * epoch's key and the previous epoch's (keyring.h) both open a ticket.
 * No seed: resumption stays disabled. */
static void srvboot_init_server(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_server_init_in*     in) {
  u8  cur[KEYRING_KEY], prev[KEYRING_KEY];
  u64 now = wired_clock_epoch_secs();
  if (!id->ticket_key) {
    wired_server_init(conn->s, in);
    return;
  }
  keyring_key(id->ticket_key, now, 0, cur);
  keyring_key(id->ticket_key, now, 1, prev);
  in->ticket_key = cur;
  wired_server_init(conn->s, in); /* copies the key out of cur */
  in->ticket_key = 0;             /* cur dies with this frame */
  sdrv_set_ticket_key_prev(&conn->s->sdrv, prev);
}

int srvboot_init(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    const wired_header*       h) {
  wired_server_init_in in = {
      id->priv,        id->pub,      id->cert_seed, id->chain,
      id->chain_count, id->san_ipv4, id->now_secs,  0};
  srvboot_init_server(conn, id, &in);
  sdrv_set_raw_alpns(&conn->s->sdrv, id->raw_alpns); /* RFC 7301 3.2 */
  wired_server_set_limits(
      conn->s, id->max_data, wired_srvloop_stream_limit(id->max_streams_bidi),
      wired_srvloop_uni_stream_limit(), id->max_datagram_frame_size);
  srvboot_set_reset_token(conn, id);
  if (!srvboot_set_cids(conn, id, h)) {
    return 0;
  }
  return wired_srvloop_init(conn->l, h->scid, h->scid_len);
}
