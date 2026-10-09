package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"time"

	"wired-guide/moqtclient"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// "moqt-22" session: SETUP exchanged on the two uni control streams.
	s := moqtclient.Dial(ctx, os.Args[1]+"/moqt")
	defer s.Conn.CloseWithError(0, "")

	// movie/init first: its SUBSCRIBE_OK, then its one-shot blob stream,
	// both read before movie is subscribed, so the next uni stream is
	// movie's.
	if reply, _ := s.Subscribe(ctx, 0, "movie/init"); !reply.Ok {
		fmt.Println("movie/init REQUEST_ERROR", reply.ErrCode)
		return
	}
	uni, err := s.AcceptUniStream(ctx)
	moqtclient.Check(err)
	_, _, initPayload := moqtclient.ReadObject(bufio.NewReader(uni))
	fmt.Printf("movie/init bytes=%d\n", len(initPayload))

	// movie: SUBSCRIBE_OK, then the current Group at once, then one more
	// Group every ~300ms as the server's clock advances.
	if reply, _ := s.Subscribe(ctx, 2, "movie"); !reply.Ok {
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
