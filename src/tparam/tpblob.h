#ifndef QUIC_TPARAM_TPBLOB_H
#define QUIC_TPARAM_TPBLOB_H

#include "sys/syscall.h"
#include "tparam/tparam.h"

/* RFC 9000 18.2 transport parameters whose value is not a single varint:
 * opaque byte strings and the preferred_address structure. Each is carried
 * as (id: varint)(length: varint)(value). */

/* Opaque-value parameter: id + length + val_len raw bytes. val may be empty
 * (val_len 0, e.g. disable_active_migration). Returns bytes written, 0 if it
 * does not fit / id out of range. */
usz quic_tparam_put_blob(u8 *buf, usz cap, u64 id, const u8 *val, usz val_len);

/* Decode one opaque parameter at buf (n readable). On success sets *id and a
 * view (*val, *val_len) into buf, returns bytes consumed; 0 if malformed. */
usz quic_tparam_get_blob(const u8 *buf, usz n, u64 *id, const u8 **val, usz *val_len);

/* RFC 9000 18.2 preferred_address value. cid is 0..20 bytes. */
struct quic_preferred_address {
    u8  ipv4[4];
    u16 ipv4_port;
    u8  ipv6[16];
    u16 ipv6_port;
    u8  cid_len;
    u8  cid[20];
    u8  reset_token[16];
};

/* Encode preferred_address as TLV (id 0x0d). Returns bytes written, 0 on
 * overflow or cid_len > 20. */
usz quic_tparam_put_preferred_address(u8 *buf, usz cap,
                                      const struct quic_preferred_address *pa);

/* Decode a preferred_address TLV at buf (n readable) into *pa. Returns bytes
 * consumed, 0 if malformed / wrong id / cid_len > 20. */
usz quic_tparam_get_preferred_address(const u8 *buf, usz n,
                                      struct quic_preferred_address *pa);

#endif
