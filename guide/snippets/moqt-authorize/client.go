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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	// "public": the policy grants it -- SUBSCRIBE_OK, then its Object.
	moqtclient.Subscribe(ctl, 0, "public")
	if reply := moqtclient.ReadSubscribeReply(r); reply.Ok {
		fmt.Printf("public SUBSCRIBE_OK alias=%d\n", reply.Alias)
		uni, err := s.AcceptUniStream(ctx)
		moqtclient.Check(err)
		_, _, payload := moqtclient.ReadObject(bufio.NewReader(uni))
		fmt.Printf("public payload=%q\n", payload)
	} else {
		fmt.Printf("public REQUEST_ERROR error_code=%d\n", reply.ErrCode)
	}

	// "secret": the policy refuses it -- REQUEST_ERROR, no stream ever
	// opens for it.
	moqtclient.Subscribe(ctl, 1, "secret")
	if reply := moqtclient.ReadSubscribeReply(r); reply.Ok {
		fmt.Printf("secret SUBSCRIBE_OK alias=%d\n", reply.Alias)
	} else {
		fmt.Printf("secret REQUEST_ERROR error_code=%d\n", reply.ErrCode)
	}
}
