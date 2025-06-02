package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"

	"github.com/hujun-open/cobra"
	"github.com/hujun-open/myflags/v2"
)

type CLI struct {
	IDiPattern string `short:"d" alias:"idi" usage:"RE pattern of IDi to match"`
	ShowEPs    bool   `short:"e" usage:"show remote tunnel endpoint of tunnels with matched IDi'"`
	ShowMsg    bool   `short:"m" usage:"show debug msgs of tunnels with matched IDi'"`
	File       struct {
		InputFile string `short:"i" required:"" usage:"SROS debug IPsec output file" noun:"1"`
	} `action:"RunFile" usage:"read SROS IPsec debug from file"`
	Netconf struct {
		Router netip.AddrPort `noun:"1" short:"r" usage:"router's address and netconf port, e.g. 192.168.1.1:830"`
		User   string         `short:"u" usage:"netconf username"`
		Passwd string         `short:"p" usage:"netconf passwrod"`
		Stream string         `noun:"2" short:"s" usage:"netconf notification stream name"`
	} `action:"RunNetconf" usage:"receive SROS IPsec debug via netconf notification"`
}

func (cli *CLI) RunNetconf(cmd *cobra.Command, args []string) {
	ctx, cancelf := context.WithCancel(context.Background())
	defer cancelf()
	em, err := newMsgAnalyzer(cli.IDiPattern)
	if err != nil {
		log.Fatal(err)
	}
	rlist := []*LogMsg{}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go cli.getNetConfEvts(ctx, wg, &rlist)
	fmt.Println("Press Enter to stop...")
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n') // Read up to the newline character
	cancelf()
	wg.Wait()
	for _, msg := range rlist {
		em.Input <- msg
	}
	close(em.Input)
	em.Wait()
	if cli.ShowEPs {
		eps := em.getEPsOutput()
		fmt.Printf("Found following matched tunnel EPs:\n%s\n", eps)

	}
	if cli.ShowMsg {
		em.printMatchedMsgs()
	}

}

func (cli *CLI) RunFile(cmd *cobra.Command, args []string) {
	f, err := os.Open(cli.File.InputFile)
	if err != nil {
		log.Fatal(err)
	}
	em, err := newMsgAnalyzer(cli.IDiPattern)
	if err != nil {
		log.Fatal(err)
	}
	m := newStringScanner(f, em.Input)
	err = m.Parse(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	em.Wait()
	if cli.ShowEPs {
		eps := em.getEPsOutput()
		fmt.Printf("Found following matched tunnel EPs:\n%s\n", eps)

	}

	if cli.ShowMsg {
		em.printMatchedMsgs()
	}
}

func defCLI() *CLI {
	r := &CLI{
		IDiPattern: ".",
		ShowEPs:    true,
		ShowMsg:    false,
	}
	r.Netconf.User = "admin"
	r.Netconf.Passwd = "admin"
	return r

}

func main() {
	cli := defCLI()
	filler := myflags.NewFiller("sridm", "Nokia SROS IPsec debug output analyzer")
	err := filler.Fill(cli)
	if err != nil {
		log.Fatal(err)
	}
	err = filler.Execute()
	if err != nil {
		log.Fatal(err)
	}

}
