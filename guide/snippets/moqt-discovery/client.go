package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"wired-guide/moqtclient"
)

// request sends one request on a fresh bidi request stream
// (draft-ietf-moq-transport-22 SS6.4.2) and prints the hub's first
// answer: REQUEST_OK (0x7) or REQUEST_ERROR (0x5) with its error code.
// The stream is left alone: resetting it would cancel the request.
func request(ctx context.Context, s *moqtclient.Session, who string, typ byte, id byte, name string) *bufio.Reader {
	label := map[byte]string{0x6: "PUBLISH_NAMESPACE", 0x50: "SUBSCRIBE_NAMESPACE"}[typ]
	// Request ID, Track Namespace (or Prefix), no parameters.
	_, r := s.Request(ctx, typ, append(append([]byte{id}, moqtclient.Namespace(strings.Split(name, "/")...)...), 0))
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

// publish opens a publisher session (one MoQT peer; closing its QUIC
// connection is how it leaves) that announces name (Request ID 0).
func publish(ctx context.Context, who, name string) *moqtclient.Session {
	s := moqtclient.Dial(ctx, os.Args[1]+"/moqt")
	request(ctx, s, who, 0x6, 0, name)
	return s
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
	lobby := publish(ctx, "lobby", "guide/lobby")
	defer lobby.Conn.CloseWithError(0, "")

	// The watcher subscribes to the prefix "guide". After REQUEST_OK the
	// hub sends one NAMESPACE per namespace already published under it:
	// the initial set.
	w := moqtclient.Dial(ctx, os.Args[1]+"/moqt")
	defer w.Conn.CloseWithError(0, "")
	watcher := request(ctx, w, "watcher", 0x50, 0, "guide")
	watch(watcher)

	// Two publishers join. Each waits for its own REQUEST_OK, and the
	// watcher then reads the NAMESPACE the hub pushed for it, so every
	// step is ordered by messages on the wire, never by a sleep.
	roomA := publish(ctx, "room-a", "guide/room-a")
	watch(watcher)
	roomB := publish(ctx, "room-b", "guide/room-b")
	defer roomB.Conn.CloseWithError(0, "")
	watch(watcher)

	// The server's authorize_namespace hook refuses "secret": the
	// publisher gets REQUEST_ERROR UNAUTHORIZED (0x1) and the watcher is
	// never told about it (the next push it sees is room-a leaving).
	request(ctx, roomB, "room-b", 0x6, 2, "guide/secret")

	// room-a leaves: closing its session withdraws its namespace, and the
	// hub pushes NAMESPACE_DONE to the watcher.
	moqtclient.Check(roomA.Conn.CloseWithError(0, ""))
	fmt.Println("room-a: session closed")
	watch(watcher)
}
