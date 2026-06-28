#ifndef QUIC_H3_REUSE_H
#define QUIC_H3_REUSE_H

/* RFC 9114 3.3: a connection may be reused for a request whose origin (URI
 * scheme, host, port) matches, provided the connection is still usable and the
 * negotiated version is compatible. */

/* True only if same origin AND connection alive AND version compatible. */
int quic_h3_conn_reusable(int same_origin, int conn_alive, int version_compatible);

#endif
