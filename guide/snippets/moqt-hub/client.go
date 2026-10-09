package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/bits"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

// varint reads a MoQT variable-length integer: the count of leading 1 bits
// in the first byte is the count of bytes that follow.
func varint(r *bufio.Reader) uint64 {
	b, err := r.ReadByte()
	check(err)
	n := bits.LeadingZeros8(^b)
	v := uint64(b) & (0xff >> (n + 1))
	for ; n > 0; n-- {
		c, err := r.ReadByte()
		check(err)
		v = v<<8 | uint64(c)
	}
	return v
}

// readMsg reads one control message: Type (varint), 16-bit Length, body.
func readMsg(r *bufio.Reader) (uint64, []byte) {
	typ := varint(r)
	var hdr [2]byte
	_, err := io.ReadFull(r, hdr[:])
	check(err)
	body := make([]byte, int(hdr[0])<<8|int(hdr[1]))
	_, err = io.ReadFull(r, body)
	check(err)
	return typ, body
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Keep the QUIC connection so main can close it before exiting.
	var conn *quic.Conn
	// Offering the WebTransport subprotocol "moqt-22" selects
	// draft-ietf-moq-transport-22 (SS6.2.1).
	d := webtransport.Transport{
		TLSClientConfig:      &tls.Config{InsecureSkipVerify: true},
		QUICConfig:           &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		ApplicationProtocols: []string{"moqt-22"},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, c *quic.Config) (*quic.Conn, error) {
			var err error
			conn, err = quic.DialAddrEarly(ctx, addr, t, c)
			return conn, err
		},
	}
	rsp, s, err := d.Dial(ctx, os.Args[1]+"/moqt", http.Header{})
	check(err)
	fmt.Println("status", rsp.StatusCode)
	if p := s.SessionState().ApplicationProtocol; p != "moqt-22" {
		log.Fatalf("server picked subprotocol %q", p)
	}

	// Each side opens one uni control stream that starts with SETUP
	// (SS6.3). Ours: Type 0x2F00 (also the stream type), Length 0, no
	// Setup Options. It stays open for the whole session.
	ctl, err := s.OpenUniStreamSync(ctx)
	check(err)
	_, err = ctl.Write([]byte{0xAF, 0x00, 0, 0})
	check(err)

	// The server's control stream, and the SETUP on it.
	srv, err := s.AcceptUniStream(ctx)
	check(err)
	typ, body := readMsg(bufio.NewReader(srv))
	fmt.Printf("recv SETUP type=%#x options=%d bytes\n", typ, len(body))
	check(conn.CloseWithError(0, ""))
}
