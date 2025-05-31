package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type LogMsg struct {
	ID                     uint
	Timestamp              time.Time
	Msg                    string
	RemoteIP               netip.Addr
	RemotePort             uint
	CountiuationOfPrevious bool
	ISPI                   string
	IsCertDump             bool
}

// SplitLines split input into a slice of line, while keeping "\n", so an empty new line in the input will be an item the result slice
func SplitLines(input string) []string {
	input = strings.Replace(input, "\r\n", "\n", -1)
	var Sep rune = 0
	news := strings.Replace(input, "\n", "\n"+string(Sep), -1)
	return strings.FieldsFunc(news, func(c rune) bool { return c == rune(0) })
}

type msgState int

const (
	lookingForMsgStart msgState = iota
	msgBegin
)

type eventState int

const (
	lookingForEventStart eventState = iota
	eventBegin
)

type parseMachine struct {
	mstate   msgState
	estate   eventState
	msgList  []*LogMsg
	curMSG   *LogMsg
	idiEPMap map[string]netip.AddrPort
}

func newParseMachine() *parseMachine {
	return &parseMachine{
		idiEPMap: make(map[string]netip.AddrPort),
	}
}

func (m *parseMachine) lookingForMsgStartHandle(curlineIndex int, lineList []string) error {
	curline := lineList[curlineIndex]
	if strings.Contains(curline, `MINOR: DEBUG #2001`) {
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
		m.mstate = msgBegin
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

func (m *parseMachine) msgBeginHandle(curlineIndex int, lineList []string) error {
	m.curMSG.Msg += lineList[curlineIndex]
	if lineList[curlineIndex] == "[...IKE message continuation]\n" || strings.HasSuffix(lineList[curlineIndex], "Cert cont:\n") {
		m.curMSG.CountiuationOfPrevious = true
	}
	if lineList[curlineIndex] == "Certificate:\n" {
		m.curMSG.IsCertDump = true
	}
	//try locate idi and remote ep
	if lineList[curlineIndex] == "IKEv2 Identification - initiator payload\n" {

		dataLine := lineList[curlineIndex+4]
		flist := strings.FieldsFunc(dataLine, func(c rune) bool { return c == ':' })
		idi := strings.TrimSpace(flist[1])
		for i := curlineIndex; i >= 0; i-- {
			if strings.HasPrefix(lineList[i], "Source: ") {
				ap, err := parseSRAddrPort(lineList[i][7:])
				if err != nil {
					return fmt.Errorf("failed to parse %v, %w", lineList[i], err)
				}
				m.idiEPMap[idi] = *ap
				break
			}
		}

	}
	if strings.HasSuffix(lineList[curlineIndex], "\"\n") && lineList[curlineIndex+1] == "\n" {

		m.msgList = append(m.msgList, m.curMSG)
		m.mstate = lookingForMsgStart

	}
	return nil

}

func (m *parseMachine) feedLine(curline int, lineList []string) error {
	var err error
	switch m.mstate {
	case lookingForMsgStart:
		err = m.lookingForMsgStartHandle(curline, lineList)
		if err != nil {
			return err
		}
	case msgBegin:
		err = m.msgBeginHandle(curline, lineList)
		if err != nil {
			return err
		}
	}
	return nil
}
func (m *parseMachine) getMatchedIdi(idiPattern string) ([]string, error) {
	r := []string{}
	re, err := regexp.Compile(idiPattern)
	if err != nil {
		return nil, err
	}

	for idi := range m.idiEPMap {
		if re.FindString(idi) != "" {
			r = append(r, idi)
		}
	}
	return r, nil
}

func (m *parseMachine) getEPsOutput(idiPattern string) (string, error) {
	idiList, err := m.getMatchedIdi(idiPattern)
	if err != nil {
		return "", err
	}
	targetIDiAPMap := make(map[string]netip.AddrPort)
	r := fmt.Sprintf("%d matched out of total %d\n", len(idiList), len(m.idiEPMap))

	for _, idi := range idiList {
		targetIDiAPMap[idi] = m.idiEPMap[idi]
		r += fmt.Sprintf("IDi '%v' ==>  %v\n", idi, m.idiEPMap[idi])

	}

	return r, nil
}

func (m *parseMachine) Parse(input string) error {
	lineList := SplitLines(input)
	const minimalLines = 2
	if len(lineList) < minimalLines {
		return fmt.Errorf("input is less than %d lines", minimalLines)
	}
	var err error
	for i := 0; i < len(lineList)-1; i++ {
		err = m.feedLine(i, lineList)
		if err != nil {
			return fmt.Errorf("failed to handle line %d and %d, %w", i+1, i+2, err)
		}
	}
	fmt.Printf("parsed %d lines\n", len(lineList))
	//check unfinished state, e.g last unfinished msg

	return nil
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

func (m *parseMachine) printIDiMatchedMsgList(idiPattern string) error {
	idiList, err := m.getMatchedIdi(idiPattern)
	if err != nil {
		return err
	}
	targetIDiAPMap := make(map[string]netip.AddrPort)
	for _, idi := range idiList {
		targetIDiAPMap[idi] = m.idiEPMap[idi]
	}
	print := false
	var n int
	for i := 0; i < len(m.msgList); {
		print = false

		for idi, ep := range targetIDiAPMap {
			if strings.Contains(m.msgList[i].Msg, idi) {
				print = true
				break
			}
			if strings.Contains(m.msgList[i].Msg, addrPortToSRFmt(ep)) {
				print = true
				break
			}
			certdn, err := ikeDNToCertDN(idi)
			if err == nil {
				if strings.Contains(m.msgList[i].Msg, certdn) {
					print = true
					break
				}
			}

		}
		if print {
			fmt.Printf("%d %v\n%v\n---------\n", m.msgList[i].ID, m.msgList[i].Timestamp, m.msgList[i].Msg)
			n = 1
			for {
				if i+n >= len(m.msgList) {
					i += n - 1
					break
				}
				if !m.msgList[i+n].CountiuationOfPrevious {
					i += n - 1
					break
				}
				fmt.Printf("%d %v\n%v\n---------\n", m.msgList[i+n].ID, m.msgList[i+n].Timestamp, m.msgList[i+n].Msg)
				n += 1
			}

		}
		i += 1

	}
	return nil
}
