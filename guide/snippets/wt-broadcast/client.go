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

func dial(ctx context.Context, addr string) (*webtransport.Session, *quic.Conn) {
	var conn *quic.Conn // the latest connection, kept so main can close it
	d := webtransport.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, q *quic.Config) (*quic.Conn, error) {
			c, err := quic.DialAddrEarly(ctx, addr, t, q)
			conn = c
			return c, err
		},
	}
	_, s, err := d.Dial(ctx, addr+"/relay", http.Header{})
	if err != nil {
		panic(err)
	}
	return s, conn
}

func main() {
	ctx := context.Background()
	a, connA := dial(ctx, os.Args[1])
	b, connB := dial(ctx, os.Args[1])
	defer connA.CloseWithError(0, "")
	defer connB.CloseWithError(0, "")

	// tag 1: the single-slot broadcast reaches every session, including A.
	a.SendDatagram([]byte{1, 's', 'l', 'o', 't'})
	for _, who := range []struct {
		name string
		s    *webtransport.Session
	}{{"A", a}, {"B", b}} {
		msg, err := who.s.ReceiveDatagram(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s recv %q\n", who.name, msg)
	}

	// tag 2: the ring delivers all three, in order, to every session.
	for _, word := range []string{"ring1", "ring2", "ring3"} {
		a.SendDatagram(append([]byte{2}, word...))
	}
	for i := 0; i < 3; i++ {
		for _, who := range []struct {
			name string
			s    *webtransport.Session
		}{{"A", a}, {"B", b}} {
			msg, err := who.s.ReceiveDatagram(ctx)
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s recv %q\n", who.name, msg)
		}
	}

	// tag 3: send_datagram_to addresses only the sender, B never sees it.
	a.SendDatagram([]byte{3, 'd', 'i', 'r', 'e', 'c', 't'})
	msg, err := a.ReceiveDatagram(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Printf("A recv %q\n", msg)
}
