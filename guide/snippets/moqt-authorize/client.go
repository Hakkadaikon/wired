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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// "moqt-22" session: SETUP exchanged on the two uni control streams.
	s := moqtclient.Dial(ctx, os.Args[1]+"/moqt")
	defer s.Conn.CloseWithError(0, "")

	// "public": the policy grants it -- SUBSCRIBE_OK on its request
	// stream, then its Object on a uni stream.
	if reply, _ := s.Subscribe(ctx, 0, "public"); reply.Ok {
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
	if reply, _ := s.Subscribe(ctx, 2, "secret"); reply.Ok {
		fmt.Printf("secret SUBSCRIBE_OK alias=%d\n", reply.Alias)
	} else {
		fmt.Printf("secret REQUEST_ERROR error_code=%d\n", reply.ErrCode)
	}
}
