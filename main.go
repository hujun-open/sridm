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
		InputFile string `short:"i" required:"" usage:"SROS debug IPsec output file"`
	} `action:"RunFile" usage:"read SROS IPsec debug from file"`
	Netconf struct {
		Router     netip.AddrPort `short:"r" usage:"router's address and netconf port, e.g. 192.168.1.1:830"`
		User       string         `short:"u" usage:"netconf username"`
		Passwd     string         `short:"p" usage:"netconf passwrod"`
		Stream     string         `short:"s" usage:"netconf notification stream name"`
		OutputFile string         `short:"o" usage:"write debug events to the specified file"`
	} `action:"RunNetconf" usage:"receive SROS IPsec debug via netconf notification"`
}

func (cli *CLI) RunNetconf(cmd *cobra.Command, args []string) {
	ctx, cancelf := context.WithCancel(context.Background())
	defer cancelf()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	ch := make(chan *Notification, 1024)
	nList := []*Notification{}
	go cli.getNetConfEvts(ctx, wg, ch)
	go func() {
		for n := range ch {
			nList = append(nList, n)
		}
		wg.Done()
	}()
	fmt.Println("Press Enter to stop...")
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n') // Read up to the newline character
	cancelf()
	wg.Wait()
	rs := ""
	for _, n := range nList {
		rs += n.ToDebugFileFormat()
	}

}

func (cli *CLI) RunFile(cmd *cobra.Command, args []string) {
	buf, err := os.ReadFile(cli.File.InputFile)
	if err != nil {
		log.Fatal(err)
	}
	m := newParseMachine()
	err = m.Parse(string(buf))
	if err != nil {
		log.Fatal(err)
	}
	if cli.ShowEPs {
		eps, err := m.getEPsOutput(cli.IDiPattern)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Found following matched tunnel EPs:\n%s\n", eps)

	}
	// for _, msg := range m.msgList {
	// 	if msg.ID == 1535 {
	// 		fmt.Println(msg.ID, "is here", msg.Msg, msg.CountiuationOfPrevious)
	// 	}
	// }
	if cli.ShowMsg {
		m.printIDiMatchedMsgList(cli.IDiPattern)
	}
	//test code
	oks := make(map[string]bool)
	for idi := range m.idiEPMap {
		oks[idi] = true
	}
	for i := 0; i < 1000; i++ {
		toCheck := fmt.Sprintf("client-%d.nokia.com", i)
		if _, ok := oks[toCheck]; !ok {
			fmt.Println(toCheck, "not found")
		}
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
