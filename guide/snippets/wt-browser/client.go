package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

func main() {
	ctx := context.Background()

	// A browser verifies serverCertificateHashes against the leaf cert's
	// own SHA-256, computed from the bytes it actually received -- this is
	// that same check, done by hand.
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}
	conn, err := quic.DialAddr(ctx, os.Args[1][len("https://"):], tlsConf, nil)
	if err != nil {
		panic(err)
	}
	leaf := conn.ConnectionState().TLS.PeerCertificates[0].Raw
	fmt.Printf("cert sha256: %x\n", sha256.Sum256(leaf))
	conn.CloseWithError(0, "")

	// Then the actual WebTransport CONNECT a browser would make to the
	// same IP literal.
	var wtConn *quic.Conn // kept so main can close it before exiting
	d := webtransport.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, q *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddrEarly(ctx, addr, t, q)
			wtConn = c
			return c, err
		},
	}
	rsp, _, err := d.Dial(ctx, os.Args[1]+"/chat", http.Header{})
	if err != nil {
		panic(err)
	}
	fmt.Println("status", rsp.StatusCode)
	wtConn.CloseWithError(0, "") // ending the connection ends its session too
}
