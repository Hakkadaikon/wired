#ifndef QUIC_IDLEDRIVE_CLOSESEND_H
#define QUIC_IDLEDRIVE_CLOSESEND_H

/* RFC 9000 10.2: an immediate close sends a CONNECTION_CLOSE and enters the
 * closing state. It is warranted either on an error or when the idle timeout
 * has expired. */

/* 1 iff a CONNECTION_CLOSE should be sent. */
int quic_idledrive_should_close(int error_occurred, int idle_expired);

#endif
