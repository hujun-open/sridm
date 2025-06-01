package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nemith/netconf"
	ncssh "github.com/nemith/netconf/transport/ssh"
	"golang.org/x/crypto/ssh"
)

// DebugEvent represents the top-level XML structure.
// require a top-level xml container of <notification>
// So, we'll make a top-level struct to encompass these.
type Notification struct {
	XMLName             xml.Name            `xml:"notification"`
	EventTime           string              `xml:"eventTime"` // Using string for time initially, then parse to time.Time if needed
	SROSLogGenericEvent SROSLogGenericEvent `xml:"sros-log-generic-event"`
}

// SROSLogGenericEvent represents the <sros-log-generic-event> element.
// The xmlns attribute is important here.
type SROSLogGenericEvent struct {
	XMLName        xml.Name `xml:"sros-log-generic-event"`
	XMLNS          string   `xml:"xmlns,attr"` // This captures the namespace URL
	SequenceNumber uint     `xml:"sequence-number"`
	Severity       string   `xml:"severity"`
	Application    string   `xml:"application"`
	EventID        int      `xml:"event-id"`
	EventName      string   `xml:"event-name"`
	RouterName     string   `xml:"router-name"`
	Subject        string   `xml:"subject"`
	Message        string   `xml:"message"`
	// EventParams    EventParams `xml:"event-params"`
}

// EventParams represents the <event-params> element.
type EventParams struct {
	XMLName xml.Name `xml:"event-params"`
	Title   string   `xml:"title"`
	Message string   `xml:"message"` // Note: This 'message' field is nested within event-params
}

func (n Notification) ToLogMsg() *LogMsg {
	t, err := time.Parse(time.RFC3339Nano, n.EventTime)
	if err != nil {
		panic(err)
	}
	return &LogMsg{
		ID:        n.SROSLogGenericEvent.SequenceNumber,
		Timestamp: t,
		Msg:       n.SROSLogGenericEvent.Message,
	}
}

func (cli *CLI) getNetConfEvts(ctx context.Context, wg *sync.WaitGroup, rlist *[]*LogMsg) {
	defer wg.Done()
	config := &ssh.ClientConfig{
		User: cli.Netconf.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(cli.Netconf.Passwd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	transport, err := ncssh.Dial(ctx, "tcp", cli.Netconf.Router.String(), config)
	if err != nil {
		panic(err)
	}
	defer transport.Close()
	count := new(int64)
	*count = 0
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(time.Second)
				fmt.Printf("\rRcvd: %d", atomic.LoadInt64(count))
			}
		}
	}()
	nh := func(msg netconf.Notification) {
		evt := new(Notification)
		bodystr := "<notification>" + string(msg.Body) + "</notification>"
		err := xml.Unmarshal([]byte(bodystr), evt)
		if err != nil {
			log.Print(err)
		}
		// outputch <- evt.ToLogMsg()
		*rlist = append(*rlist, evt.ToLogMsg())
		atomic.AddInt64(count, 1)
	}

	session, err := netconf.Open(transport, netconf.WithNotificationHandler(nh))
	if err != nil {
		log.Printf("failed to create netconf session, %v", err)
		return
	}
	defer session.Close(context.Background())
	err = session.CreateSubscription(ctx, netconf.WithStreamOption(cli.Netconf.Stream))
	if err != nil {
		log.Printf("failed to create subscription to stream %v, %v", cli.Netconf.Stream, err)
		return
	}
	<-ctx.Done()
}
