package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

// sendRound opens a fresh bidi stream, writes parts as separate writes (so
// the server sees each as its own reassembly delta), closes it, and
// returns the server's reply.
func sendRound(ctx context.Context, s *webtransport.Session, parts ...string) string {
	str, err := s.OpenStreamSync(ctx)
	if err != nil {
		panic(err)
	}
	for i, p := range parts {
		str.Write([]byte(p))
		if i < len(parts)-1 {
			time.Sleep(100 * time.Millisecond) // let the hold take effect first
		}
	}
	str.Close()
	ack, _ := io.ReadAll(str)
	return string(ack)
}

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
	_, s, err := d.Dial(ctx, os.Args[1]+"/upload", http.Header{})
	if err != nil {
		panic(err)
	}
	defer conn.CloseWithError(0, "")

	fmt.Println("ack1", sendRound(ctx, s, "part1", "part2"))
	fmt.Println("ack2", sendRound(ctx, s, "abort"))
}
