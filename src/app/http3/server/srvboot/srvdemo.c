#include "app/http3/server/srvboot/srvdemo.h"

#include "common/bytes/util/bytes.h"
#include "common/fmt/fmt.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/server/server.h"

/* RFC 9000 17.2: a connection id is at most 20 bytes. */
#define SRVDEMO_SCID_MAX 20

void wired_srvboot_demo(
    wired_srvboot_id*        id,
    wired_srvboot_demo_keys* k,
    u8                       base,
    const char*              scid) {
  usz n = wired_cstr_len(scid);
  for (usz i = 0; i < 32; i++) {
    k->priv[i] = (u8)(base + i);
    k->seed[i] = (u8)(base + 0x40 + i);
    k->rnd[i]  = (u8)(base + 0x60 + i);
  }
  wired_x25519_base(k->pub, k->priv);
  bytes_memset(id, 0, sizeof *id);
  id->priv      = k->priv;
  id->pub       = k->pub;
  id->cert_seed = k->seed;
  id->random    = k->rnd;
  id->scid      = (const u8*)scid;
  id->scid_len  = (u8)(n < SRVDEMO_SCID_MAX ? n : SRVDEMO_SCID_MAX);
}

int wired_srvboot_cert_sha256(const wired_srvboot_id* id, u8 out[32]) {
  static wired_server  s; /* scratch, too large for the stack */
  wired_server_init_in in = {
      id->priv,        id->pub,      id->cert_seed, id->chain,
      id->chain_count, id->san_ipv4, id->now_secs,  0};
  wired_server_init(&s, &in);
  if (s.sdrv.cert_count == 0) return 0;
  wired_sha256(s.sdrv.certs[0].p, s.sdrv.certs[0].n, out);
  return 1;
}

int wired_srvboot_log_fingerprint(i64 fd, const wired_srvboot_id* id) {
  u8   d[32];
  char line[32 * 3 + 32];
  usz  n = 0;
  if (!wired_srvboot_cert_sha256(id, d)) return 0;
  n = wired_snprintf(line, sizeof line, "cert sha-256 fingerprint: %02x", d[0]);
  for (usz i = 1; i < 32; i++)
    n += wired_snprintf(line + n, sizeof line - n, ":%02x", d[i]);
  wired_dprintf(fd, "%s\n", line);
  return 1;
}
