package main

import (
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

// msgAnalyzer get LogMsg via Input, save it to msgList,
// identify IDi and remote EP, saved them in idiEPMap,
// IDiPattern is the RE pattern to match on IDi,
type msgAnalyzer struct {
	Input      chan *LogMsg
	IdiPattern string
	idiRegexp  *regexp.Regexp
	idiEPMap   map[string]netip.AddrPort
	wg         *sync.WaitGroup
	msgList    []*LogMsg
}

const inputChanDepth = 102400

func newMsgAnalyzer(idiPattern string) (*msgAnalyzer, error) {
	r := &msgAnalyzer{
		Input:      make(chan *LogMsg, inputChanDepth),
		IdiPattern: idiPattern,
		idiEPMap:   make(map[string]netip.AddrPort),
		wg:         new(sync.WaitGroup),
		msgList:    []*LogMsg{},
	}
	var err error
	r.idiRegexp, err = regexp.Compile(r.IdiPattern)
	if err != nil {
		return nil, err
	}
	r.wg.Add(1)
	go r.Recv()
	return r, nil
}

func (em *msgAnalyzer) Recv() {
	defer em.wg.Done()

	for msg := range em.Input {
		em.msgList = append(em.msgList, msg)
		//get EP
		lineList := SplitLines(msg.Msg)
	L1:
		for i := range lineList {
			if lineList[i] == "[...IKE message continuation]" || strings.HasSuffix(lineList[i], "Cert cont:") {
				msg.CountiuationOfPrevious = true
			}
			if lineList[i] == "IKEv2 Identification - initiator payload" {
				if i+4 < len(lineList) {
					dataLine := lineList[i+4]
					flist := strings.FieldsFunc(dataLine, func(c rune) bool { return c == ':' })
					idi := strings.TrimSpace(flist[1])
					for n := i; n >= 0; n-- {
						if strings.HasPrefix(lineList[n], "Source: ") {
							ap, err := parseSRAddrPort(lineList[n][7:])
							if err != nil {
								log.Printf("failed to parse line get EP: %v, %v", lineList[n], err)
								break L1

							}
							em.idiEPMap[idi] = *ap
							break L1
						}
					}
				}
			}
		}

	}
}

func (em *msgAnalyzer) GetMatchedIdi() []string {
	r := []string{}
	for idi := range em.idiEPMap {
		if em.idiRegexp.FindString(idi) != "" {
			r = append(r, idi)
		}
	}
	return r
}

func (em *msgAnalyzer) GetMatachedMsg() []*LogMsg {
	previousMatched := false
	r := []*LogMsg{}
	matchedIDIs := em.GetMatchedIdi()
	for _, msg := range em.msgList {
		if em.matchMsg(msg, matchedIDIs) {
			r = append(r, msg)
			previousMatched = true
		} else {
			if previousMatched && msg.CountiuationOfPrevious {
				r = append(r, msg)
			} else {
				previousMatched = false
			}
		}
	}
	return r
}

func (em *msgAnalyzer) matchMsg(msg *LogMsg, matchedIDi []string) bool {
	targetIDiAPMap := make(map[string]netip.AddrPort)
	for _, idi := range matchedIDi {
		targetIDiAPMap[idi] = em.idiEPMap[idi]
	}
	matched := false
	for idi, ep := range targetIDiAPMap {
		if strings.Contains(msg.Msg, idi) {
			matched = true
			break
		}
		if strings.Contains(msg.Msg, addrPortToSRFmt(ep)) {
			matched = true
			break
		}
		certdn, err := ikeDNToCertDN(idi)
		if err == nil {
			if strings.Contains(msg.Msg, certdn) {
				matched = true
				break
			}
		}

	}
	return matched
}

func (em *msgAnalyzer) Wait() {
	em.wg.Wait()
}

func (em *msgAnalyzer) getEPsOutput() string {
	idiList := em.GetMatchedIdi()
	r := fmt.Sprintf("%d matched out of total %d\n", len(idiList), len(em.idiEPMap))
	for _, idi := range idiList {
		r += fmt.Sprintf("IDi '%v' ==>  %v\n", idi, em.idiEPMap[idi])

	}
	return r
}

func (em *msgAnalyzer) printMatchedMsgs() {
	for _, msg := range em.GetMatachedMsg() {
		fmt.Printf("%d %v\n%v\n-------\n", msg.ID, msg.Timestamp, msg.Msg)
	}
}
