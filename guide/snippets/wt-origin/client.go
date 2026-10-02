package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

// dial sends one Extended CONNECT with the given Origin header and prints
// its status, closing whatever connection resulted before returning.
func dial(addr, origin string) {
	ctx := context.Background()
	var conn *quic.Conn
	d := webtransport.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, q *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddrEarly(ctx, addr, t, q)
			conn = c
			return c, err
		},
	}
	hdr := http.Header{}
	hdr.Set("Origin", origin)
	rsp, _, err := d.Dial(ctx, addr+"/chat", hdr)
	if rsp == nil {
		panic(err)
	}
	fmt.Println(origin, "status", rsp.StatusCode)
	// Closing the whole connection (not the session separately) keeps the
	// server's teardown log a single, deterministic "conn closed by peer"
	// line per dial.
	conn.CloseWithError(0, "")
}

func main() {
	addr := os.Args[1]
	dial(addr, "https://ok.example")
	dial(addr, "https://evil.example")
}
