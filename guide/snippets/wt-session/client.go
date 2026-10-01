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

func main() {
	ctx := context.Background()
	var conn *quic.Conn // the latest connection, kept so main can close it
	d := webtransport.Transport{
		TLSClientConfig:      &tls.Config{InsecureSkipVerify: true}, // self-signed demo cert
		QUICConfig:           &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		ApplicationProtocols: []string{"chat"},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, q *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddrEarly(ctx, addr, t, q)
			conn = c
			return c, err
		},
	}

	rsp, _, err := d.Dial(ctx, os.Args[1]+"/forbidden", http.Header{})
	if err == nil {
		panic("/forbidden was accepted")
	}
	fmt.Println("/forbidden:", rsp.StatusCode)

	rsp, s, err := d.Dial(ctx, os.Args[1]+"/chat", http.Header{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("/chat: %d protocol %q\n", rsp.StatusCode, s.SessionState().ApplicationProtocol)

	conn.CloseWithError(0, "") // ending the connection ends its session too
	fmt.Println("closed /chat")
}
