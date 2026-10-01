package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
	"wired-guide/moqtclient"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
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
	_, s, err := d.Dial(ctx, os.Args[1]+"/moqt", http.Header{})
	moqtclient.Check(err)
	defer conn.CloseWithError(0, "")

	// The server opens the control stream and sends SETUP on it.
	ctl, err := s.AcceptStream(ctx)
	moqtclient.Check(err)
	r := bufio.NewReader(ctl)
	moqtclient.ReadMsg(r) // SETUP

	// movie/init first (its SUBSCRIBE_OK and one-shot blob stream arrive
	// before movie's, since both are sent and processed on the same
	// ordered control stream).
	moqtclient.Subscribe(ctl, 0, "movie/init")
	if reply := moqtclient.ReadSubscribeReply(r); !reply.Ok {
		fmt.Println("movie/init REQUEST_ERROR", reply.ErrCode)
		return
	}
	uni, err := s.AcceptUniStream(ctx)
	moqtclient.Check(err)
	_, _, initPayload := moqtclient.ReadObject(bufio.NewReader(uni))
	fmt.Printf("movie/init bytes=%d\n", len(initPayload))

	// movie: SUBSCRIBE_OK, then the current Group at once, then one more
	// Group every ~300ms as the server's clock advances.
	moqtclient.Subscribe(ctl, 1, "movie")
	if reply := moqtclient.ReadSubscribeReply(r); !reply.Ok {
		fmt.Println("movie REQUEST_ERROR", reply.ErrCode)
		return
	}
	const groups = 4
	for i := 0; i < groups; i++ {
		u, err := s.AcceptUniStream(ctx)
		moqtclient.Check(err)
		_, group, payload := moqtclient.ReadObject(bufio.NewReader(u))
		fmt.Printf("movie group=%d bytes=%d\n", group, len(payload))
	}
}
