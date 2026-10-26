#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_TOKEN_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_TOKEN_H

#include "app/http3/server/srvrun/srvrun_impl_protos4.h"

/* RFC 9000 8.1: the address validation token gate (srvrun_note.c) and
 * NEW_TOKEN tokens (srvrun_token.c). */

/* srvrun_token_verdict's outcomes for a fresh Initial's token. */
#define SRVRUN_TOK_SERVE 0 /* serve it (validated or not) */
#define SRVRUN_TOK_RETRY 1 /* answer with a Retry (RFC 9000 8.1.2/8.1.3) */
#define SRVRUN_TOK_CLOSE 2 /* close with INVALID_TOKEN (RFC 9000 8.1.2) */
int srvrun_token_verdict(
    const srvrun_step_ctx* ctx,
    const lhdr*            h,
    u32                    version,
    wired_span*            odcid,
    int*                   validated);
/* NEW_TOKEN tokens (srvrun_token.c): the address binding is the 16-byte
 * IP address || the be32 QUIC version. */
#define SRVRUN_NEWTOK_BIND 20
#define SRVRUN_NEWTOK_LEN (1 + NEWTOKEN_WIRE_LEN)
usz srvrun_newtok_make(
    const sockaddr* peer, u32 version, u64 now, u8 out[SRVRUN_NEWTOK_LEN]);
int srvrun_newtok_ok(
    const sockaddr* peer, u32 version, wired_span token, u64 now);
usz srvrun_newtok_seal(srvrun_conn* c, u64 now, u8* out, usz cap);
/** What srvrun_send_new_token compares a step's outcome against: the
 * validated path and the confirmation before it. */
typedef struct {
  pathsel_key valid;
  u8          confirmed;
  u8          seeded;
} srvrun_newtok_mark;
srvrun_newtok_mark srvrun_newtok_mark_of(const srvrun_conn* c);
void               srvrun_send_new_token(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const srvrun_newtok_mark* m);
int srvrun_send_initial_close(
    const srvrun_step_ctx* ctx, wired_mspan dg, u64 code);
void srvrun_retry_scid_distinct(u8 scid[8], wired_span dcid);
int  srvrun_can_serve(const wired_srvboot_id* id);

#endif
