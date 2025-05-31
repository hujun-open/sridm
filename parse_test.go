package main

import (
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	buf, err := os.ReadFile("testlog.txt")
	if err != nil {
		t.Fatal(err)
	}
	m := newParseMachine()
	err = m.Parse(string(buf))
	if err != nil {
		t.Fatal(err)
	}
	m.printIDiMatchedMsgList("smallcellee-10")
}
