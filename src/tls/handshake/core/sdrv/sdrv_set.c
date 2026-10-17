#include "tls/handshake/core/sdrv/sdrv_impl.h"

static int sdrv_set_cid(u8* dst, u8* dst_len, wired_span cid);

void sdrv_set_preferred_address(sdrv* s, const sdrv_pref_addr* p) {
  bytes_memcpy(s->pref_v4, p->v4, 4);
  bytes_memcpy(s->pref_v6, p->v6, 16);
  bytes_memcpy(s->pref_cid, p->cid, p->cid_len);
  bytes_memcpy(s->pref_token, p->token, 16);
  s->pref_v4_port = p->v4_port;
  s->pref_v6_port = p->v6_port;
  s->pref_cid_len = p->cid_len;
}

u32 sdrv_wire_version(const sdrv* s) {
  if (s->negotiated_version) return s->negotiated_version;
  return s->client_version ? s->client_version : VERSION_1;
}

/* Copy a connection id (<=20 bytes) into dst, recording its length. Returns 1
 * on success, 0 if len exceeds 20. */
static int sdrv_set_cid(u8* dst, u8* dst_len, wired_span cid) {
  if (cid.n > 20) return 0;
  for (usz i = 0; i < cid.n; i++) dst[i] = cid.p[i];
  *dst_len = (u8)cid.n;
  return 1;
}

void sdrv_set_group(sdrv* s, u16 group) { s->group = group; }

int sdrv_set_cids(sdrv* s, wired_span odcid, wired_span iscid) {
  return sdrv_set_cid(s->odcid, &s->odcid_len, odcid) &&
         sdrv_set_cid(s->iscid, &s->iscid_len, iscid) &&
         sdrv_set_cid(s->tp_odcid, &s->tp_odcid_len, odcid);
}

int sdrv_set_cids_retried(
    sdrv* s, wired_span odcid, wired_span iscid, wired_span true_odcid) {
  return sdrv_set_cid(s->odcid, &s->odcid_len, odcid) &&
         sdrv_set_cid(s->iscid, &s->iscid_len, iscid) &&
         sdrv_set_cid(s->tp_odcid, &s->tp_odcid_len, true_odcid);
}

int sdrv_set_retry_scid(sdrv* s, wired_span rscid) {
  return sdrv_set_cid(s->rscid, &s->rscid_len, rscid);
}
