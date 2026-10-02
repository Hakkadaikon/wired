package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
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
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, c *quic.Config) (*quic.Conn, error) {
			var err error
			conn, err = quic.DialAddrEarly(ctx, addr, t, c)
			return conn, err
		},
	}
	rsp, s, err := d.Dial(ctx, os.Args[1]+"/deliver", http.Header{})
	moqtclient.Check(err)
	fmt.Println("status", rsp.StatusCode)

	// A "go" datagram tells the server to send one of each delivery mode.
	moqtclient.Check(s.SendDatagram([]byte("go")))

	// Lossy: one OBJECT_DATAGRAM, bounded by the connection's own QUIC
	// datagram size, dropped (never retried) if the network loses it.
	dg, err := s.ReceiveDatagram(ctx)
	moqtclient.Check(err)
	dr := bufio.NewReader(bytes.NewReader(dg))
	moqtclient.Varint(dr) // Type 0x00: every field present on the wire
	alias := moqtclient.Varint(dr)
	group := moqtclient.Varint(dr)
	objID := moqtclient.Varint(dr)
	_, err = dr.ReadByte() // raw Publisher Priority byte, not a varint
	moqtclient.Check(err)
	payload, err := io.ReadAll(dr)
	moqtclient.Check(err)
	fmt.Printf("datagram alias=%d group=%d id=%d payload=%q\n", alias, group, objID, payload)

	// Reliable: one Object stream, its 20000-byte blob split at the 16 KiB
	// per-Object cap into two Objects that arrive complete, in order.
	uni, err := s.AcceptUniStream(ctx)
	moqtclient.Check(err)
	ur := bufio.NewReader(uni)
	salias, sgroup, obj1 := moqtclient.ReadObject(ur)
	moqtclient.Varint(ur) // second Object's ID delta
	obj2 := make([]byte, moqtclient.Varint(ur))
	_, err = io.ReadFull(ur, obj2)
	moqtclient.Check(err)
	fmt.Printf("stream alias=%d group=%d object_1=%d bytes object_2=%d bytes total=%d bytes\n",
		salias, sgroup, len(obj1), len(obj2), len(obj1)+len(obj2))

	conn.CloseWithError(0, "")
}
