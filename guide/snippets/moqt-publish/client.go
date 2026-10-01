package main

import (
	"bufio"
	"bytes"
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

// str appends a length-prefixed string (shorter than 128 bytes, so its
// length fits a one-byte varint).
func str(b []byte, s string) []byte {
	return append(append(b, byte(len(s))), s...)
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
	d := webtransport.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, c *quic.Config) (*quic.Conn, error) {
			var err error
			conn, err = quic.DialAddrEarly(ctx, addr, t, c)
			return conn, err
		},
	}
	rsp, s, err := d.Dial(ctx, os.Args[1]+"/moqt", http.Header{})
	check(err)
	fmt.Println("status", rsp.StatusCode)

	// The server opens the control stream and sends SETUP on it.
	ctl, err := s.AcceptStream(ctx)
	check(err)
	r := bufio.NewReader(ctl)
	typ, body := readMsg(r)
	fmt.Printf("recv SETUP type=%#x options=%d bytes\n", typ, len(body))

	// SUBSCRIBE (0x3) on the same stream: Request ID 0, Track Namespace
	// ("guide"), Track Name ("greeting"), no parameters.
	sub := append(str(str([]byte{0, 1}, "guide"), "greeting"), 0)
	_, err = ctl.Write(append([]byte{0x3, 0, byte(len(sub))}, sub...))
	check(err)
	fmt.Println("send SUBSCRIBE guide/greeting")

	typ, body = readMsg(r)
	if typ != 0x4 {
		log.Fatalf("expected SUBSCRIBE_OK, got type %#x", typ)
	}
	alias := varint(bufio.NewReader(bytes.NewReader(body)))
	fmt.Printf("recv SUBSCRIBE_OK track_alias=%d\n", alias)

	// The object arrives on its own uni stream: a SUBGROUP_HEADER (Type,
	// Track Alias, Group ID), then Object ID delta, payload length, payload.
	uni, err := s.AcceptUniStream(ctx)
	check(err)
	u := bufio.NewReader(uni)
	varint(u) // Type 0x70: no Subgroup ID, default priority, no properties
	alias, group, id := varint(u), varint(u), varint(u)
	payload := make([]byte, varint(u))
	_, err = io.ReadFull(u, payload)
	check(err)
	fmt.Printf("recv object track_alias=%d group=%d id=%d payload=%q\n", alias, group, id, payload)
	check(conn.CloseWithError(0, ""))
}
