#ifndef TLS_HANDSHAKE_CORE_FULLHS_FULLHS_IMPL_H
#define TLS_HANDSHAKE_CORE_FULLHS_FULLHS_IMPL_H

/* Internal to the fullhs*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/kdf/keys/discard_driver.h"
#include "crypto/kdf/keys/keyset.h"
#include "crypto/pki/encoding/x509/san.h"
#include "crypto/pki/encoding/x509/validity.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "tls/handshake/core/fullhs/fullhs.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/certverify.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/hsdriver.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/keys/schedule_drive/keyschedule.h"

/* Record every cert as an offset into the transcript copy of cert_msg (the
 * bytes fullhs_tr_add appended at `base`), so the views outlive the caller's
 * datagram buffer for the rest of the handshake. */
typedef struct {
  usz                   base;
  wired_span            cert_msg;
  const tls_cert_entry* e;
  usz                   n;
} fullhs_chain_rec_in;

int  fullhs_tr_add(fullhs* h, const u8* msg, usz len);
void fullhs_tr_hash(const fullhs* h, u8 out[SHA256_DIGEST]);
int  fullhs_fold_finished(fullhs* h, const u8* fin, usz len);
int  fullhs_order_ok(fullhs* h, u8 msg_type);
int  fullhs_policy_ok(const fullhs* h, const u8* cert, usz n);

#endif
