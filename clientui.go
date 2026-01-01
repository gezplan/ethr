// -----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
// -----------------------------------------------------------------------------
package main

import (
	"fmt"
	"sync/atomic"
	"time"
)

type clientUI struct {
	title string
}

func (u *clientUI) fini() {
}

func (u *clientUI) getTitle() string {
	return u.title
}

func (u *clientUI) printMsg(format string, a ...interface{}) {
	s := fmt.Sprintf(format, a...)
	logInfo(s)
	fmt.Println(s)
}

func (u *clientUI) printErr(format string, a ...interface{}) {
	s := fmt.Sprintf(format, a...)
	logError(s)
	fmt.Printf("\x1b[31m%s\x1b[0m\n", s)
}

func (u *clientUI) printDbg(format string, a ...interface{}) {
	if loggingLevel == LogLevelDebug {
		s := fmt.Sprintf(format, a...)
		logDebug(s)
		fmt.Println(s)
	}
}

func (u *clientUI) paint(seconds uint64) {
}

func (u *clientUI) emitTestResultBegin() {
}

func (u *clientUI) emitTestHdr(test *ethrTest) {
	s := []string{"ServerAddress", "Proto", "Bits/s", "Conn/s", "Pkt/s"}
	fmt.Println("-----------------------------------------------------------")
	fmt.Printf("%-15s %-5s %7s %7s %7s\n", s[0], s[1], s[2], s[3], s[4])
}

func (u *clientUI) emitLatencyHdr() {
	s := []string{"Avg", "Min", "50%", "90%", "95%", "99%", "99.9%", "99.99%", "Max"}
	fmt.Println("-----------------------------------------------------------------------------------------")
	fmt.Printf("%9s %9s %9s %9s %9s %9s %9s %9s %9s\n", s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8])
}

func (u *clientUI) emitLatencyResults(remote, proto string, avg, min, max, p50, p90, p95, p99, p999, p9999 time.Duration) {
	logLatency(remote, proto, avg, min, max, p50, p90, p95, p99, p999, p9999)
	fmt.Printf("%9s %9s %9s %9s %9s %9s %9s %9s %9s\n",
		durationToString(avg), durationToString(min),
		durationToString(p50), durationToString(p90),
		durationToString(p95), durationToString(p99),
		durationToString(p999), durationToString(p9999),
		durationToString(max))

	// Send latency stats to hub if callback is set
	if hubStatsCallback != nil {
		latencyStats := &LatencyStats{
			Avg:   avg,
			Min:   min,
			Max:   max,
			P50:   p50,
			P90:   p90,
			P95:   p95,
			P99:   p99,
			P999:  p999,
			P9999: p9999,
		}

		// First, try to use hubActiveTest if available (external mode)
		if hubActiveTest != nil {
			protoEnum := TCP
			switch proto {
			case "udp":
				protoEnum = UDP
			case "icmp":
				protoEnum = ICMP
			}
			testType := hubActiveTest.testID.Type
			hubStatsCallback(remote, protoEnum, testType, 0, 0, 0, latencyStats, nil, hubActiveTest)
			return
		}

		// Fallback: Find the test for this remote via gSessions lookup
		gSessionLock.RLock()
		var targetTest *ethrTest
		var testType EthrTestType = Latency
		for _, session := range gSessions {
			if session.remoteIP == remote {
				for _, test := range session.tests {
					// Look for Latency or Ping type tests
					if test.testID.Type == Latency || test.testID.Type == Ping {
						targetTest = test
						testType = test.testID.Type
						break
					}
				}
				if targetTest != nil {
					break
				}
			}
		}
		gSessionLock.RUnlock()

		if targetTest != nil {
			protoEnum := TCP
			switch proto {
			case "udp":
				protoEnum = UDP
			case "icmp":
				protoEnum = ICMP
			}
			hubStatsCallback(remote, protoEnum, testType, 0, 0, 0, latencyStats, nil, targetTest)
		}
	}
}

func (u *clientUI) emitTestResultEnd() {
}

func (u *clientUI) emitStats(netStats ethrNetStat) {
}

func (u *clientUI) printTestResults(s []string) {
}

func initClientUI(title string) {
	cli := &clientUI{title}
	ui = cli
}

var gInterval uint64
var gNoConnectionStats bool

func printBwTestDivider(p EthrProtocol) {
	switch p {
	case TCP:
		ui.printMsg("- - - - - - - - - - - - - - - - - - - - - - -")
	case UDP:
		ui.printMsg("- - - - - - - - - - - - - - - - - - - - - - - - - - - -")
	}
}

func printBwTestHeader(p EthrProtocol) {
	switch p {
	case TCP:
		ui.printMsg("[  ID ]   Protocol    Interval      Bits/s")
	case UDP:
		// Printing packets only makes sense for UDP as it is a datagram protocol.
		// For TCP, TCP itself decides how to chunk the stream to send as packets.
		ui.printMsg("[  ID ]   Protocol    Interval      Bits/s    Pkts/s")
	}
}

func printBwTestResult(p EthrProtocol, fd string, t0, t1, bw, pps uint64) {
	switch p {
	case TCP:
		ui.printMsg("[%5s]     %-5s    %03d-%03d sec   %7s", fd,
			protoToString(p), t0, t1, bytesToRate(bw))
	case UDP:
		ui.printMsg("[%5s]     %-5s    %03d-%03d sec   %7s   %7s", fd,
			protoToString(p), t0, t1, bytesToRate(bw), ppsToString(pps))
	}
}

func printTestResult(test *ethrTest, seconds float64) {
	if test.testID.Type == Bandwidth &&
		(test.testID.Protocol == TCP || test.testID.Protocol == UDP) {
		if gInterval == 0 {
			printBwTestDivider(test.testID.Protocol)
			printBwTestHeader(test.testID.Protocol)
		}
		cbw := uint64(0)
		cpps := uint64(0)
		ccount := 0
		test.connListDo(func(ec *ethrConn) {
			bw := atomic.SwapUint64(&ec.bw, 0)
			pps := atomic.SwapUint64(&ec.pps, 0)
			// Use actual elapsed time for precise rate calculation
			bw = uint64(float64(bw) / seconds)
			if !gNoConnectionStats {
				fd := fmt.Sprintf("%5d", ec.fd)
				printBwTestResult(test.testID.Protocol, fd, gInterval, gInterval+1, bw, pps)
			}
			cbw += bw
			cpps += pps
			ccount++
		})
		if ccount > 1 || gNoConnectionStats {
			printBwTestResult(test.testID.Protocol, "SUM", gInterval, gInterval+1, cbw, cpps)
			if !gNoConnectionStats {
				printBwTestDivider(test.testID.Protocol)
			}
		}
		logResults([]string{test.session.remoteIP, protoToString(test.testID.Protocol),
			bytesToRate(cbw), "", ppsToString(cpps), ""})

		// Send stats to hub if callback is set
		if hubStatsCallback != nil {
			hubStatsCallback(test.session.remoteIP, test.testID.Protocol, test.testID.Type, cbw, 0, cpps, nil, nil, test)
		}
	} else if test.testID.Type == Cps {
		if gInterval == 0 {
			ui.printMsg("- - - - - - - - - - - - - - - - - - ")
			ui.printMsg("Protocol    Interval      Conn/s")
		}
		cps := atomic.SwapUint64(&test.testResult.cps, 0)
		ui.printMsg("  %-5s    %03d-%03d sec   %7s",
			protoToString(test.testID.Protocol),
			gInterval, gInterval+1, cpsToString(cps))
		logResults([]string{test.session.remoteIP, protoToString(test.testID.Protocol),
			"", cpsToString(cps), "", ""})

		// Send stats to hub if callback is set
		if hubStatsCallback != nil {
			hubStatsCallback(test.session.remoteIP, test.testID.Protocol, test.testID.Type, 0, cps, 0, nil, nil, test)
		}
	} else if test.testID.Type == Pps {
		if gInterval == 0 {
			ui.printMsg("- - - - - - - - - - - - - - - - - - - - - - -")
			ui.printMsg("Protocol    Interval      Bits/s    Pkts/s")
		}
		bw := atomic.SwapUint64(&test.testResult.bw, 0)
		pps := atomic.SwapUint64(&test.testResult.pps, 0)
		ui.printMsg("  %-5s    %03d-%03d sec   %7s   %7s",
			protoToString(test.testID.Protocol),
			gInterval, gInterval+1, bytesToRate(bw), ppsToString(pps))
		logResults([]string{test.session.remoteIP, protoToString(test.testID.Protocol),
			bytesToRate(bw), "", ppsToString(pps), ""})

		// Send stats to hub if callback is set
		if hubStatsCallback != nil {
			hubStatsCallback(test.session.remoteIP, test.testID.Protocol, test.testID.Type, bw, 0, pps, nil, nil, test)
		}
	} else if test.testID.Type == MyTraceRoute {
		if gCurHops > 0 {
			ui.printMsg("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ")
			ui.printMsg("Host: %-40s    Sent    Recv        Last         Avg        Best        Wrst", test.session.remoteIP)
		}
		for i := 0; i < gCurHops; i++ {
			hopData := gHop[i]
			if hopData.addr != "" {
				if hopData.sent > 0 {
					avg := time.Duration(0)
					if hopData.rcvd > 0 {
						avg = time.Duration(hopData.total.Nanoseconds() / int64(hopData.rcvd))
					}
					ui.printMsg("%2d.|--%-40s   %5d   %5d   %9s   %9s   %9s   %9s", i+1, hopData.addr, hopData.sent, hopData.rcvd,
						durationToString(hopData.last), durationToString(avg), durationToString(hopData.best), durationToString(hopData.worst))
				}
			} else {
				ui.printMsg("%2d.|--%-40s   %5s   %5s   %9s   %9s   %9s   %9s", i+1, "???", "-", "-", "-", "-", "-", "-")
			}
		}

		// Send MyTraceRoute stats to hub if callback is set
		if hubStatsCallback != nil && gCurHops > 0 {
			// Copy hop data to send to hub
			hopsCopy := make([]ethrHopData, gCurHops)
			copy(hopsCopy, gHop[:gCurHops])
			hubStatsCallback(test.session.remoteIP, test.testID.Protocol, test.testID.Type, 0, 0, 0, nil, hopsCopy, test)
		}
	}
	gInterval++
}

func (u *clientUI) emitTestResult(s *ethrSession, proto EthrProtocol, seconds float64) {
	var testList = []EthrTestType{Bandwidth, Cps, Pps, TraceRoute, MyTraceRoute}

	for _, testType := range testList {
		test, found := s.tests[EthrTestID{proto, testType}]
		if found && test.isActive {
			printTestResult(test, seconds)
		}
	}
}
