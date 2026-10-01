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
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, q *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddrEarly(ctx, addr, t, q)
			conn = c
			return c, err
		},
	}
	_, s, err := d.Dial(ctx, os.Args[1]+"/open", http.Header{})
	if err != nil {
		panic(err)
	}
	defer conn.CloseWithError(0, "")

	uni, err := s.AcceptUniStream(ctx)
	if err != nil {
		panic(err)
	}
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(uni)
		done <- b
	}()

	// Each word drives the server-opened stream one round further, and we
	// wait for its ack before sending the next -- so "bye" only reaches the
	// server after "more" was fully applied.
	for _, word := range []string{"more", "bye"} {
		str, err := s.OpenStreamSync(ctx)
		if err != nil {
			panic(err)
		}
		str.Write([]byte(word))
		str.Close()
		ack, _ := io.ReadAll(str)
		fmt.Printf("%s: %q\n", word, ack)
	}

	fmt.Printf("uni stream: %q\n", <-done)
}
