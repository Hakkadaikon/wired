#ifndef WIRED_KEYLOG_KEYLOG_H
#define WIRED_KEYLOG_KEYLOG_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/**
 * @file
 * Build and append one NSS Key Log Format line (the SSLKEYLOGFILE format
 * read by Wireshark and other decrypters): `<Label> <ClientRandom-hex>
 * <Secret-hex>\n`. This layer only formats the line and appends it via
 * wired_fio_append; deriving the secret and locating the log path from an
 * environment variable are the caller's responsibility.
 */

/**
 * Append one key log line to path: label + ' ' + hex(client_random) + ' '
 * + hex(secret) + '\n'. Creates path if it does not exist (wired_fio_append
 * semantics).
 *
 * @param path          NUL-terminated key log file path
 * @param label         NUL-terminated label, e.g.
 *                      "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
 * @param client_random 32-byte TLS client random
 * @param secret        secret bytes to hex-encode
 * @return bytes written on success; WIRED_FIO_ETOOBIG when the line would
 *         exceed the internal line buffer; a negative -errno when the
 *         underlying append fails
 */
ssz wired_keylog_append(
    const char *path,
    const char *label,
    const u8    client_random[32],
    quic_span   secret);

#endif
