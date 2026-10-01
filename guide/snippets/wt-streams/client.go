package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
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

	uni, err := s.AcceptUniStream(ctx)
	if err != nil {
		panic(err)
	}
	welcome, _ := io.ReadAll(uni)
	fmt.Printf("uni from server: %q\n", welcome)

	str, err := s.OpenStreamSync(ctx)
	if err != nil {
		panic(err)
	}
	str.Write([]byte("hello"))
	str.Close() // FIN: the server echoes once the stream is complete
	echo, _ := io.ReadAll(str)
	fmt.Printf("sent %q, echoed %q\n", "hello", echo)
}
