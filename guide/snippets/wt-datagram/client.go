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
	rsp, s, err := d.Dial(ctx, os.Args[1]+"/echo", http.Header{})
	if err != nil {
		panic(err)
	}
	defer conn.CloseWithError(0, "")
	fmt.Println("status", rsp.StatusCode)

	s.SendDatagram([]byte("ping"))
	fmt.Printf("sent %q\n", "ping")
	b, err := s.ReceiveDatagram(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Printf("recv %q\n", b)
}
