package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	buf, err := os.Open("testlog.txt")
	if err != nil {
		t.Fatal(err)
	}
	em, err := newMsgAnalyzer("smallcellee-10")
	if err != nil {
		log.Fatal(err)
	}
	m := newStringScanner(buf, em.Input)
	err = m.Parse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	em.Wait()
	for _, msg := range em.GetMatachedMsg() {
		fmt.Printf("%d %v\n%v\n-------\n", msg.ID, msg.Timestamp, msg.Msg)
	}

}
