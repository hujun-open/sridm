package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// logMsg is debug msg, one msg is a single debug msg, one IPsec debug event might contain multiple msgs, like a IKE_AUTH packet debug output might contain two msgs
type LogMsg struct {
	ID                     uint
	Timestamp              time.Time
	Msg                    string
	CountiuationOfPrevious bool //if true, means this msg is a continuation of previous msg, e.g. a fragment
}

// SplitLines split input into a slice of line, while keeping "\n", so an empty new line in the input will be an item the result slice
func SplitLines(input string) []string {
	buf := bytes.NewBufferString(input)
	s := bufio.NewScanner(buf)
	r := []string{}
	for s.Scan() {
		r = append(r, s.Text())
	}
	return r
}

type msgState int

const (
	lookingForMsgStart msgState = iota
	msgBegin
	lookingForMsgEnd
)

// stringScanner scan input from src (e.g. a file), divide strings into LogMsg, send out via output,
// implemented via a FSM
type stringScanner struct {
	src    *bufio.Scanner
	state  msgState
	curMSG *LogMsg
	output chan *LogMsg
}

func newStringScanner(input io.Reader, out chan *LogMsg) *stringScanner {
	return &stringScanner{
		src:    bufio.NewScanner(input),
		output: out,
	}
}

func (m *stringScanner) lookingForMsgStartHandle(curline string) error {
	if strings.Contains(curline, `DEBUG #2001`) {
		flist := strings.Fields(curline)
		id, err := strconv.Atoi(flist[0])
		if err != nil {
			return err
		}
		t, err := time.Parse("2006/01/02 15:04:05.000", fmt.Sprintf("%v %v", flist[1], flist[2]))
		if err != nil {
			return err
		}
		m.curMSG = &LogMsg{
			ID:        uint(id),
			Timestamp: t,
		}
		m.state = msgBegin
	}
	return nil
}

// parse SR ipsec debug msg formatted EP into netip.AddrPort
func parseSRAddrPort(s string) (*netip.AddrPort, error) {
	s = strings.TrimSpace(s)
	flist := strings.FieldsFunc(s, func(c rune) bool { return c == '[' })
	ports := flist[1][0 : len(flist[1])-1]
	var err error
	var ap netip.AddrPort
	if strings.Contains(s, ":") {
		//ipv6, example 2001:beef::100[500]
		ap, err = netip.ParseAddrPort(fmt.Sprintf("[%v]:%v", flist[0], ports))
	} else {
		//ipv4, example 172.100.100.1[500]
		ap, err = netip.ParseAddrPort(fmt.Sprintf("%v:%v", flist[0], ports))
	}
	if err != nil {
		return nil, err
	}
	return &ap, nil
}

// convert ap to SR ipsec debug msg formatted EP
//
//2001:beef::100[500], 172.100.100.1[500]
func addrPortToSRFmt(ap netip.AddrPort) string {
	if ap.Addr().Is4() {
		return fmt.Sprintf("%v:[%d]", ap.Addr().String(), ap.Port())
	}
	return fmt.Sprintf("%v[%d]", ap.Addr().String(), ap.Port())
}

func (m *stringScanner) msgBeginHandle(curline string) error {
	m.curMSG.Msg += curline

	if strings.HasSuffix(curline, "\"\n") {
		m.state = lookingForMsgEnd
	}
	return nil

}

func (m *stringScanner) lookingForMsgEndHandle(line string) error {
	if line == "\n" {
		m.state = lookingForMsgStart
		m.output <- m.curMSG
		return nil
	}
	m.state = msgBegin
	return m.msgBeginHandle(line)
}

func (m *stringScanner) feedLine(line string) error {
	var err error
	switch m.state {
	case lookingForMsgStart:
		err = m.lookingForMsgStartHandle(line)
		if err != nil {
			return err
		}
	case lookingForMsgEnd:
		err = m.lookingForMsgEndHandle(line)
		if err != nil {
			return err
		}
	case msgBegin:
		err = m.msgBeginHandle(line)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *stringScanner) Parse(ctx context.Context) error {
	defer close(m.output)
	var err error
	for m.src.Scan() {
		err = m.feedLine(m.src.Text() + "\n")
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return m.src.Err()
		default:
		}
	}

	return m.src.Err()
}

// convert subject DN in ikev2 pkt debug output ('Country=US, StateOrProv=CA, Locality=Sunnyvale, OrgName=Nokia, OrgUnitName=NI, CommonName=SeGW-2, Email=segw2@gmail.com')
// to certificate debug output ` C=US, ST=CA, L=Sunnyvale, O=Nokia, OU=NI, CN=SeGW-2/emailAddress=segw2@gmail.com`
// another cert debug output, but apprently IKEv2 doesn't support all types in it: ` C=US, ST=CA, L=Sunnyvale, O=Nokia, OU=NI, CN=SeGW-2/emailAddress=segw2@nokia.com/serialNumber=100022/businessCategory=Telecom, L=localSeGW/postalCode=93300/name=SeGW-name/description=A SEGW/role=GW`
func ikeDNToCertDN(ikedn string) (string, error) {
	typeMap := map[string]string{
		"Country":     "C",
		"StateOrProv": "ST",
		"Locality":    "L",
		"OrgName":     "O",
		"OrgUnitName": "OU",
		"CommonName":  "CN",
		"Email":       "emailAddress",
	}
	//parseIKEOuput parse s (IDi), into a slice, each item is two item slice, first is the type translated into cert debug output, 2nd is the value
	parseIKEOuput := func(s string) ([][]string, string, error) {
		if !strings.Contains(s, "=") {
			return nil, "", fmt.Errorf("not a DN")
		}
		flist := strings.FieldsFunc(s, func(c rune) bool { return c == ',' })
		r := [][]string{}
		var email string
		for _, f := range flist {
			clist := strings.FieldsFunc(f, func(c rune) bool { return c == '=' })
			ikeType := strings.TrimSpace(clist[0])
			val := strings.TrimSpace(clist[1])
			if certType, ok := typeMap[ikeType]; ok {
				if certType == "emailAddress" {
					email = val
				} else {
					r = append(r, []string{certType, val})
				}

			} else {
				return nil, email, fmt.Errorf("%v is not supported", ikeType)
			}
		}
		return r, email, nil
	}
	tlist, email, err := parseIKEOuput(ikedn)
	if err != nil {
		return "", err
	}
	r := ""
	for _, item := range tlist {
		key := item[0]
		val := item[1]
		if key == "CN" && email != "" {
			val += fmt.Sprintf("/emailAddress=%v", email)
		}
		r += fmt.Sprintf("%v=%v, ", key, val)
	}
	r = strings.TrimSpace(r)
	return r[:len(r)-1], nil
}
