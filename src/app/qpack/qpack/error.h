#ifndef QUIC_QPACK_ERROR_H
#define QUIC_QPACK_ERROR_H

/* RFC 9204 6, 8.3. QPACK connection error codes, registered in the HTTP/3
 * Error Codes registry alongside the QUIC_H3_* codes (frame.h). */

/* The decoder failed to interpret an encoded field section and cannot
 * continue decoding that field section. */
#define QUIC_QPACK_DECOMPRESSION_FAILED 0x0200

/* The decoder failed to interpret an encoder instruction received on the
 * encoder stream. */
#define QUIC_QPACK_ENCODER_STREAM_ERROR 0x0201

/* The encoder failed to interpret a decoder instruction received on the
 * decoder stream. */
#define QUIC_QPACK_DECODER_STREAM_ERROR 0x0202

#endif
