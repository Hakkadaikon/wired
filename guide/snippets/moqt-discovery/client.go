package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"

	"wired-guide/moqtclient"
)

// dial opens one WebTransport session to the hub (one MoQT peer); the
// QUIC connection is returned so the caller can close it, which is how a
// peer leaves.
func dial(ctx context.Context, url string) (*webtransport.Session, *quic.Conn) {
	var conn *quic.Conn
	d := webtransport.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		DialAddr: func(ctx context.Context, addr string, t *tls.Config, c *quic.Config) (*quic.Conn, error) {
			var err error
			conn, err = quic.DialAddrEarly(ctx, addr, t, c)
			return conn, err
		},
	}
	_, s, err := d.Dial(ctx, url+"/moqt", http.Header{})
	moqtclient.Check(err)
	return s, conn
}

// request opens a fresh bidi request stream (draft-ietf-moq-transport-19
// SS3.3), sends one request on it and prints the hub's first answer:
// REQUEST_OK (0x7) or REQUEST_ERROR (0x5) with its error code. The
// stream is left alone: resetting it would cancel the request (SS3.3.3).
func request(ctx context.Context, s *webtransport.Session, who string, typ byte, id byte, name string) *bufio.Reader {
	st, err := s.OpenStreamSync(ctx)
	moqtclient.Check(err)
	label := map[byte]string{0x6: "PUBLISH_NAMESPACE", 0x50: "SUBSCRIBE_NAMESPACE"}[typ]
	// Request ID, Track Namespace (or Prefix), no parameters.
	moqtclient.WriteMsg(st, typ, append(append([]byte{id}, moqtclient.Namespace(strings.Split(name, "/")...)...), 0))
	r := bufio.NewReader(st)
	switch t, body := moqtclient.ReadMsg(r); t {
	case 0x7:
		fmt.Printf("%s: %s %s -> REQUEST_OK\n", who, label, name)
	case 0x5:
		code := moqtclient.Varint(bufio.NewReader(bytes.NewReader(body)))
		fmt.Printf("%s: %s %s -> REQUEST_ERROR error_code=%d\n", who, label, name, code)
	default:
		log.Fatalf("%s answered with type %#x", label, t)
	}
	return r
}

// publish opens a publisher session that announces name (Request ID 0).
func publish(ctx context.Context, who, name string) (*webtransport.Session, *quic.Conn) {
	s, conn := dial(ctx, os.Args[1])
	request(ctx, s, who, 0x6, 0, name)
	return s, conn
}

// watch reads the next push on the SUBSCRIBE_NAMESPACE stream and prints
// it with the namespace suffix (the fields after the prefix "guide").
func watch(r *bufio.Reader) {
	typ, body := moqtclient.ReadMsg(r)
	label := map[uint64]string{0x8: "NAMESPACE", 0xE: "NAMESPACE_DONE"}[typ]
	if label == "" {
		log.Fatalf("unexpected push type %#x", typ)
	}
	fmt.Printf("watcher: %s %s\n", label, strings.Join(moqtclient.ReadNamespace(body), "/"))
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A namespace already published before anyone watches.
	_, lobby := publish(ctx, "lobby", "guide/lobby")
	defer lobby.CloseWithError(0, "")

	// The watcher subscribes to the prefix "guide". After REQUEST_OK the
	// hub sends one NAMESPACE per namespace already published under it:
	// the initial set.
	w, wConn := dial(ctx, os.Args[1])
	defer wConn.CloseWithError(0, "")
	watcher := request(ctx, w, "watcher", 0x50, 0, "guide")
	watch(watcher)

	// Two publishers join. Each waits for its own REQUEST_OK, and the
	// watcher then reads the NAMESPACE the hub pushed for it, so every
	// step is ordered by messages on the wire, never by a sleep.
	_, roomA := publish(ctx, "room-a", "guide/room-a")
	watch(watcher)
	roomB, roomBConn := publish(ctx, "room-b", "guide/room-b")
	defer roomBConn.CloseWithError(0, "")
	watch(watcher)

	// The server's authorize_namespace hook refuses "secret": the
	// publisher gets REQUEST_ERROR UNAUTHORIZED (0x1) and the watcher is
	// never told about it (the next push it sees is room-a leaving).
	request(ctx, roomB, "room-b", 0x6, 2, "guide/secret")

	// room-a leaves: closing its session withdraws its namespace, and the
	// hub pushes NAMESPACE_DONE to the watcher.
	moqtclient.Check(roomA.CloseWithError(0, ""))
	fmt.Println("room-a: session closed")
	watch(watcher)
}
