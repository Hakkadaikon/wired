#ifndef QUIC_FRAME_CLOSE_CONVERT_H
#define QUIC_FRAME_CLOSE_CONVERT_H

/* RFC 9000 10.2.3: an application CONNECTION_CLOSE (type 0x1d) must not appear
 * in Initial or Handshake packets; it is converted to a transport
 * CONNECTION_CLOSE (type 0x1c) carrying APPLICATION_ERROR. */

#define QUIC_CLOSE_TRANSPORT 0x1c
#define QUIC_CLOSE_APPLICATION 0x1d

/* True if an application close in an Initial/Handshake packet needs conversion
 * to a transport close. */
int quic_close_needs_convert(int is_app_close, int in_handshake);

/* The frame type to use after conversion: transport CONNECTION_CLOSE (0x1c). */
int quic_close_converted_type(void);

#endif
