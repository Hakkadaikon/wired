#ifndef QUIC_TLS_ENCEXT_CHECK_H
#define QUIC_TLS_ENCEXT_CHECK_H

/* RFC 9001 8.2: an endpoint that receives a TLS EncryptedExtensions message
 * without the quic_transport_parameters extension MUST close the connection
 * with a missing_extension alert. */

/* found_tp_ext is 1 if the 0x39 extension was seen in EncryptedExtensions. */
int quic_encext_has_tp(int found_tp_ext);

/* Returns 1 if the requirement is met (the extension was present), else 0. */
int quic_encext_required_ok(int found_tp);

#endif
