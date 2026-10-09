package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"wired-guide/moqtclient"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The session handshake of the hub page: subprotocol "moqt-22", then
	// one SETUP each way on the two uni control streams.
	s := moqtclient.Dial(ctx, os.Args[1]+"/moqt")
	defer s.Conn.CloseWithError(0, "")
	fmt.Println("status", s.Status)
	fmt.Printf("recv SETUP type=%#x options=%d bytes\n", s.SetupType, len(s.SetupOptions))

	// SUBSCRIBE (0x3) on a bidi request stream of its own: Request ID 0,
	// Track Namespace ("guide"), Track Name ("greeting"), no parameters.
	// The reply, SUBSCRIBE_OK, comes back on the same stream.
	fmt.Println("send SUBSCRIBE guide/greeting")
	reply, _ := s.Subscribe(ctx, 0, "greeting")
	if !reply.Ok {
		log.Fatalf("SUBSCRIBE refused, error_code=%d", reply.ErrCode)
	}
	fmt.Printf("recv SUBSCRIBE_OK track_alias=%d\n", reply.Alias)

	// The object arrives on its own uni stream: a SUBGROUP_HEADER (Type,
	// Track Alias, Group ID), then Object ID delta, payload length, payload.
	uni, err := s.AcceptUniStream(ctx)
	moqtclient.Check(err)
	u := bufio.NewReader(uni)
	// The hub sends Type 0x70: FIRST_OBJECT (0x40) set, no Subgroup ID
	// field, default priority, no properties.
	moqtclient.Varint(u)
	alias, group, id := moqtclient.Varint(u), moqtclient.Varint(u), moqtclient.Varint(u)
	payload := make([]byte, moqtclient.Varint(u))
	_, err = io.ReadFull(u, payload)
	moqtclient.Check(err)
	fmt.Printf("recv object track_alias=%d group=%d id=%d payload=%q\n", alias, group, id, payload)
}
