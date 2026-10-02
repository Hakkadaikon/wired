package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

func main() {
	ctx := context.Background()
	var conn *quic.Conn // kept so main can close it before exiting
	d := webtransport.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // self-signed demo cert
		QUICConfig:      &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, q *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddrEarly(ctx, addr, t, q)
			conn = c
			return c, err
		},
	}
	_, s, err := d.Dial(ctx, os.Args[1]+"/lifecycle", http.Header{})
	if err != nil {
		panic(err)
	}
	fmt.Println("session open")

	// The first datagram makes the server send WT_DRAIN_SESSION, the second
	// makes it close the session.
	for _, msg := range []string{"one", "two"} {
		if err := s.SendDatagram([]byte(msg)); err != nil {
			panic(err)
		}
	}

	// Any session call returns the close once it arrives.
	_, err = s.AcceptUniStream(ctx)
	var se *webtransport.SessionError
	if !errors.As(err, &se) {
		panic(err)
	}
	fmt.Printf("closed by server: code %d, reason %q\n", se.ErrorCode, se.Message)
	conn.CloseWithError(0, "")
}
