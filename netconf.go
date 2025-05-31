package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"strings"
	"sync"
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
	SequenceNumber int      `xml:"sequence-number"`
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

func (n Notification) ToDebugFileFormat() string {
	t, err := time.Parse(time.RFC3339Nano, n.EventTime)
	if err != nil {
		panic(err)
	}
	header := fmt.Sprintf("%d %s %s: %s #%d %v %v",
		n.SROSLogGenericEvent.SequenceNumber,
		t.Format("2006/01/02 15:04:05.000 MST"),
		strings.ToUpper(n.SROSLogGenericEvent.Severity),
		strings.ToUpper(n.SROSLogGenericEvent.Application),
		n.SROSLogGenericEvent.EventID,
		n.SROSLogGenericEvent.RouterName,
		n.SROSLogGenericEvent.Subject,
	)
	return header + "\n\"" + n.SROSLogGenericEvent.Message + "\"\n"

}

func (cli *CLI) getNetConfEvts(ctx context.Context, wg *sync.WaitGroup, outputch chan *Notification) {
	defer wg.Done()
	defer close(outputch)
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
	count := 0
	nh := func(msg netconf.Notification) {
		evt := new(Notification)
		bodystr := "<notification>" + string(msg.Body) + "</notification>"
		err := xml.Unmarshal([]byte(bodystr), evt)
		if err != nil {
			log.Print(err)
		}
		outputch <- evt
		count++
		fmt.Printf("\rGot %d", count)
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
