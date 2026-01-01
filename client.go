// -----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
// -----------------------------------------------------------------------------
package main

import (
	//	"bytes"
	//	"crypto/tls"
	//	"crypto/x509"

	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	//	"io"
	//	"io/ioutil"
	"net"
	//	"net/http"
	"os"
	"os/signal"

	//	"sort"
	//	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	done       = 0
	timeout    = 1
	interrupt  = 2
	disconnect = 3
)

func handleInterrupt(toStop chan<- int) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		toStop <- interrupt
	}()
}

func runDurationTimer(d time.Duration, toStop chan int) {
	go func() {
		dSeconds := uint64(d.Seconds())
		if dSeconds == 0 {
			return
		}
		time.Sleep(d)
		// Sleep extra 200ms to ensure stats print for correct number of seconds.
		time.Sleep(200 * time.Millisecond)
		toStop <- timeout
	}()
}

func initClient(title string) {
	initClientUI(title)
}

func handshakeWithServer(test *ethrTest, conn net.Conn) (err error) {
	var ethrMsg *EthrMsg
	// If test has a sessionID (from control channel), include it in the SYN
	// This allows server to track stats per session for multi-client support
	if test.sessionID != "" {
		ethrMsg = createSynMsgWithSession(test.testID, test.clientParam, test.sessionID)
	} else {
		ethrMsg = createSynMsg(test.testID, test.clientParam)
	}
	err = sendSessionMsg(conn, ethrMsg)
	if err != nil {
		ui.printDbg("Failed to send SYN message to Ethr server. Error: %v", err)
		return
	}
	ethrMsg = recvSessionMsg(conn)
	if ethrMsg.Type != EthrAck {
		ui.printDbg("Failed to receive ACK message from Ethr server. Error: %v", err)
		err = os.ErrInvalid
	}
	return
}

func getServerIPandPort(server string) (string, string, string, error) {
	hostName := ""
	hostIP := ""
	port := ""
	u, err := url.Parse(server)
	if err == nil && u.Hostname() != "" {
		hostName = u.Hostname()
		if u.Port() != "" {
			port = u.Port()
		} else {
			// Only implicitly derive port in External client mode.
			if gIsExternalClient {
				switch u.Scheme {
				case "http":
					port = "80"
				case "https":
					port = "443"
				}
			}
		}
	} else {
		hostName, port, err = net.SplitHostPort(server)
		if err != nil {
			hostName = server
		}
	}
	_, hostIP, err = ethrLookupIP(hostName)
	return hostName, hostIP, port, err
}

func runClient(testID EthrTestID, title string, clientParam EthrClientParam, server string) {
	initClient(title)
	hostName, hostIP, port, err := getServerIPandPort(server)
	if err != nil {
		return
	}
	ip := net.ParseIP(hostIP)
	if ip != nil {
		if ip.To4() != nil {
			gIPVersion = ethrIPv4
		} else {
			gIPVersion = ethrIPv6
		}
	} else {
		return
	}

	if gIsExternalClient {
		if testID.Protocol != ICMP && port == "" {
			ui.printErr("In external mode, port cannot be empty for TCP tests.")
			return
		}
	} else {
		if port != "" {
			ui.printErr("In client mode, port (%s) cannot be specified in destination (%s).", port, server)
			ui.printMsg("Hint: Use external mode (-x).")
			return
		}
		port = gEthrPortStr
	}
	ui.printMsg("Using destination: %s, ip: %s, port: %s", hostName, hostIP, port)
	test, err := newTest(hostIP, testID, clientParam)
	if err != nil {
		ui.printErr("Failed to create the new test.")
		return
	}
	test.remoteAddr = server
	test.remoteIP = hostIP
	test.remotePort = port
	if testID.Protocol == ICMP {
		test.dialAddr = hostIP
	} else {
		test.dialAddr = fmt.Sprintf("[%s]:%s", hostIP, port)
	}
	runTest(test)
}

func runTest(test *ethrTest) {
	toStop := make(chan int, 16)
	gap := test.clientParam.Gap
	duration := test.clientParam.Duration
	test.isActive = true

	// Reset cumulative totals for new test
	atomic.StoreUint64(&test.testResult.totalBw, 0)
	atomic.StoreUint64(&test.testResult.totalPps, 0)

	switch test.testID.Protocol {
	case TCP:
		switch test.testID.Type {
		case Bandwidth:
			if test.clientParam.NoControlChannel {
				// No control channel mode (-ncc): use in-band sync on data connections
				// This is useful when server is behind a load balancer
				tcpRunBandwidthTestInBandSync(test, toStop, duration)
			} else {
				// Control channel mode (default): separate control connection for
				// coordination and results exchange (iPerf-style)
				tcpRunBandwidthTestWithCtrl(test, toStop, duration)
			}
		case Latency:
			startStatsTimer()
			runDurationTimer(duration, toStop)
			go runTCPLatencyTest(test, gap, toStop)
		case Cps:
			if test.clientParam.NoControlChannel {
				// No control channel mode: pure connection establishment test
				startStatsTimer()
				runDurationTimer(duration, toStop)
				go tcpRunCpsTest(test)
			} else {
				// Control channel mode: deterministic test end with results exchange
				tcpRunCpsTestWithCtrl(test, toStop, duration)
			}
		case Ping:
			startStatsTimer()
			runDurationTimer(duration, toStop)
			go clientRunPingTest(test, gap, test.clientParam.WarmupCount)
		case TraceRoute:
			VerifyPermissionForTest(test.testID)
			startStatsTimer()
			runDurationTimer(duration, toStop)
			go tcpRunTraceRoute(test, gap, toStop)
		case MyTraceRoute:
			VerifyPermissionForTest(test.testID)
			startStatsTimer()
			runDurationTimer(duration, toStop)
			go tcpRunMyTraceRoute(test, gap, toStop)
		}
	case UDP:
		switch test.testID.Type {
		case Bandwidth, Pps:
			if test.clientParam.NoControlChannel {
				// No control channel mode (-ncc)
				startStatsTimer()
				runDurationTimer(duration, toStop)
				runUDPBandwidthAndPpsTest(test)
			} else {
				// Control channel mode (default) - critical for UDP to see server-side receive rate
				runUDPBandwidthAndPpsTestWithCtrl(test, toStop, duration)
			}
		}
	case ICMP:
		VerifyPermissionForTest(test.testID)
		switch test.testID.Type {
		case Ping:
			startStatsTimer()
			runDurationTimer(duration, toStop)
			go clientRunPingTest(test, gap, test.clientParam.WarmupCount)
		case TraceRoute:
			startStatsTimer()
			runDurationTimer(duration, toStop)
			go icmpRunTraceRoute(test, gap, toStop)
		case MyTraceRoute:
			startStatsTimer()
			runDurationTimer(duration, toStop)
			go icmpRunMyTraceRoute(test, gap, toStop)
		}
	}
	handleInterrupt(toStop)
	reason := <-toStop
	stopStatsTimer()
	close(test.done)
	if test.testID.Type == Ping {
		time.Sleep(2 * time.Second)
	}
	switch reason {
	case done:
		ui.printMsg("Ethr done, measurement complete.")
	case timeout:
		ui.printMsg("Ethr done, duration: " + duration.String() + ".")
		ui.printMsg("Hint: Use -d parameter to change duration of the test.")
	case interrupt:
		ui.printMsg("Ethr done, received interrupt signal.")
	case disconnect:
		ui.printMsg("Ethr done, connection terminated.")
	}
}

// tcpRunBandwidthTestInBandSync runs bandwidth test with in-band synchronization
// This is used when -ncc flag is specified (no separate control channel)
// Useful when server is behind a load balancer where control/data may hit different servers
func tcpRunBandwidthTestInBandSync(test *ethrTest, toStop chan int, duration time.Duration) {
	var wg sync.WaitGroup

	// Phase 1: Establish first connection and do sync handshake
	// This connection does both sync AND data transfer (no separate control channel)
	firstConn, err := ethrDialInc(TCP, test.dialAddr, 0)
	if err != nil {
		ui.printErr("Error dialing connection: %v", err)
		toStop <- disconnect
		return
	}

	// Do basic handshake (SYN/ACK)
	err = handshakeWithServer(test, firstConn)
	if err != nil {
		ui.printErr("Failed in handshake with the server. Error: %v", err)
		firstConn.Close()
		toStop <- disconnect
		return
	}

	// Do sync handshake on first connection
	sendTime := time.Now()
	ethrMsg := createSyncStartMsg()
	err = sendSessionMsg(firstConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send SyncStart message. Error: %v", err)
		firstConn.Close()
		toStop <- disconnect
		return
	}

	// Wait for server's response
	ethrMsg = recvSessionMsg(firstConn)
	recvTime := time.Now()
	if ethrMsg.Type != EthrSyncReady {
		ui.printErr("Failed to receive SyncReady message from server.")
		firstConn.Close()
		toStop <- disconnect
		return
	}
	delayNs := ethrMsg.SyncReady.DelayNs
	rtt := recvTime.Sub(sendTime)
	rttNs := rtt.Nanoseconds()

	// Calculate start time and send RTT back to server
	var startTime time.Time
	if delayNs == 0 {
		// Single-client mode: 3-way handshake
		// Send RTT back to server, then START immediately
		ethrMsg = createSyncGoMsg(rttNs)
		err = sendSessionMsg(firstConn, ethrMsg)
		if err != nil {
			ui.printErr("Failed to send SyncGo message. Error: %v", err)
			firstConn.Close()
			toStop <- disconnect
			return
		}
		// Start immediately after sending
		startTime = time.Now()
	} else {
		// Multi-client mode: align to server's existing stats timer
		oneWayLatency := rtt / 2
		adjustedDelay := time.Duration(delayNs) - oneWayLatency
		if adjustedDelay < 0 {
			adjustedDelay = 0
		}
		startTime = time.Now().Add(adjustedDelay)

		// Send RTT back to server
		ethrMsg = createSyncGoMsg(rttNs)
		err = sendSessionMsg(firstConn, ethrMsg)
		if err != nil {
			ui.printErr("Failed to send SyncGo message. Error: %v", err)
			firstConn.Close()
			toStop <- disconnect
			return
		}

		// Wait until the adjusted start time
		waitUntilTime(startTime)
	}

	// Phase 2: Establish remaining connections (they skip sync on server side)
	var connections []net.Conn
	connections = append(connections, firstConn)

	for th := uint32(1); th < test.clientParam.NumThreads; th++ {
		conn, err := ethrDialInc(TCP, test.dialAddr, uint16(th))
		if err != nil {
			ui.printErr("Error dialing connection: %v", err)
			continue
		}

		// Do basic handshake (SYN/ACK) - server will skip sync for these
		err = handshakeWithServer(test, conn)
		if err != nil {
			ui.printErr("Failed in handshake with the server. Error: %v", err)
			conn.Close()
			continue
		}
		connections = append(connections, conn)
	}

	// Phase 3: Start all threads simultaneously
	startBarrier := make(chan struct{})
	for _, conn := range connections {
		wg.Add(1)
		go func(c net.Conn) {
			<-startBarrier // All threads wait here
			runTCPBandwidthTestHandler(test, c, &wg)
		}(conn)
	}

	// Set the test start time and start stats timer
	test.startTime = startTime
	startStatsTimerAt(startTime)

	// Release all threads simultaneously - this is when data transfer begins
	close(startBarrier)

	// Start duration timer
	runDurationTimer(duration, toStop)

	go func() {
		wg.Wait()
		toStop <- disconnect
	}()
}

// tcpRunBandwidthTestWithCtrl runs bandwidth test with a separate control channel (iPerf-style)
// The control channel is used for:
// 1. Test parameter exchange and session ID assignment
// 2. Synchronized test start
// 3. Results exchange at the end (server sends its measured stats to client)
func tcpRunBandwidthTestWithCtrl(test *ethrTest, toStop chan int, duration time.Duration) {
	var wg sync.WaitGroup

	// Phase 1: Establish control connection
	ctrlConn, err := ethrDial(TCP, test.dialAddr)
	if err != nil {
		ui.printErr("Error dialing control connection: %v", err)
		toStop <- disconnect
		return
	}
	test.ctrlConn = ctrlConn

	// Generate unique session ID
	sessionID := generateSessionID()
	test.sessionID = sessionID

	// Do handshake on control connection
	ethrMsg := createSynMsg(test.testID, test.clientParam)
	err = sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send SYN message on control channel. Error: %v", err)
		ctrlConn.Close()
		toStop <- disconnect
		return
	}

	ethrMsg = recvSessionMsg(ctrlConn)
	if ethrMsg.Type != EthrAck {
		ui.printErr("Failed to receive ACK message from server on control channel.")
		ctrlConn.Close()
		toStop <- disconnect
		return
	}

	// Send control start message with session ID
	ethrMsg = createCtrlStartMsg(sessionID)
	err = sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send CtrlStart message. Error: %v", err)
		ctrlConn.Close()
		toStop <- disconnect
		return
	}

	// Do time sync handshake
	sendTime := time.Now()
	ethrMsg = createSyncStartMsg()
	err = sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send SyncStart message on control channel. Error: %v", err)
		ctrlConn.Close()
		toStop <- disconnect
		return
	}

	ethrMsg = recvSessionMsg(ctrlConn)
	recvTime := time.Now()
	if ethrMsg.Type != EthrSyncReady {
		ui.printErr("Failed to receive SyncReady message from server.")
		ctrlConn.Close()
		toStop <- disconnect
		return
	}
	delayNs := ethrMsg.SyncReady.DelayNs
	rtt := recvTime.Sub(sendTime)
	rttNs := rtt.Nanoseconds()

	// Calculate start time
	var startTime time.Time
	if delayNs == 0 {
		// Single-client mode
		ethrMsg = createSyncGoMsg(rttNs)
		err = sendSessionMsg(ctrlConn, ethrMsg)
		if err != nil {
			ui.printErr("Failed to send SyncGo message. Error: %v", err)
			ctrlConn.Close()
			toStop <- disconnect
			return
		}
		startTime = time.Now()
	} else {
		// Multi-client mode
		oneWayLatency := rtt / 2
		adjustedDelay := time.Duration(delayNs) - oneWayLatency
		if adjustedDelay < 0 {
			adjustedDelay = 0
		}
		startTime = time.Now().Add(adjustedDelay)

		ethrMsg = createSyncGoMsg(rttNs)
		err = sendSessionMsg(ctrlConn, ethrMsg)
		if err != nil {
			ui.printErr("Failed to send SyncGo message. Error: %v", err)
			ctrlConn.Close()
			toStop <- disconnect
			return
		}
		waitUntilTime(startTime)
	}

	// Phase 2: Establish data connections (separate from control)
	var connections []net.Conn
	for th := uint32(0); th < test.clientParam.NumThreads; th++ {
		conn, err := ethrDialInc(TCP, test.dialAddr, uint16(th))
		if err != nil {
			ui.printErr("Error dialing data connection: %v", err)
			continue
		}

		// Handshake includes session ID so server can associate this with control channel
		err = handshakeWithServer(test, conn)
		if err != nil {
			ui.printErr("Failed in handshake with the server. Error: %v", err)
			conn.Close()
			continue
		}
		connections = append(connections, conn)
	}

	if len(connections) == 0 {
		ui.printErr("No data connections established.")
		ctrlConn.Close()
		toStop <- disconnect
		return
	}

	// Phase 3: Start all data transfer threads simultaneously
	startBarrier := make(chan struct{})
	for _, conn := range connections {
		wg.Add(1)
		go func(c net.Conn) {
			<-startBarrier
			runTCPBandwidthTestHandler(test, c, &wg)
		}(conn)
	}

	test.startTime = startTime
	startStatsTimerAt(startTime)
	close(startBarrier)

	// Track whether test completed normally (vs early disconnect)
	testEnding := make(chan struct{})

	// Wait for duration, then request results BEFORE signaling test completion
	// If duration is 0, run forever (only stop on interrupt)
	if duration > 0 {
		go func() {
			// Wait for the test duration
			time.Sleep(duration)

			// Signal that we're ending the test intentionally
			close(testEnding)

			// Close all data connections first - this signals server to stop reading
			// and ensures all data is accounted for before we request results
			for _, conn := range connections {
				conn.Close()
			}

			// Wait for data goroutines to finish
			wg.Wait()

			// Wait a bit more for server side to finish processing
			time.Sleep(200 * time.Millisecond)

			// Now request results - server has finished counting all data
			requestServerResults(test, ctrlConn, duration)
			ctrlConn.Close()

			// Now signal that test should stop
			toStop <- timeout
		}()
	}

	// Also monitor data connections - if they all disconnect early, test ends
	go func() {
		wg.Wait()
		// Only send disconnect if test wasn't ending intentionally
		select {
		case <-testEnding:
			// Test ending normally, don't send disconnect
		default:
			toStop <- disconnect
		}
	}()
}

// requestServerResults sends test end signal and receives server's measured results
func requestServerResults(test *ethrTest, ctrlConn net.Conn, duration time.Duration) {
	if ctrlConn == nil {
		ui.printDbg("requestServerResults: ctrlConn is nil")
		return
	}

	ui.printDbg("Requesting results from server...")

	// Send test end message
	ethrMsg := createCtrlTestEndMsg()
	err := sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printDbg("Failed to send CtrlTestEnd message. Error: %v", err)
		return
	}

	ui.printDbg("Sent CtrlTestEnd, waiting for results...")

	// Receive server results
	ethrMsg = recvSessionMsg(ctrlConn)
	ui.printDbg("Received message type: %v", ethrMsg.Type)

	if ethrMsg.Type == EthrCtrlResults && ethrMsg.CtrlResults != nil {
		test.ctrlResults = ethrMsg.CtrlResults

		// Calculate duration in seconds
		durationSecs := duration.Seconds()
		if durationSecs < 1 {
			durationSecs = 1
		}

		// Check if this is a CPS test
		if test.testID.Type == Cps {
			// CPS-specific summary
			clientTotalCps := atomic.LoadUint64(&test.testResult.totalCps)
			serverTotalCps := test.ctrlResults.Connections

			ui.printMsg("- - - - - - - - - - - - - - - - - - - - - - - - -")
			ui.printMsg("[ ID]   Interval        Conn/s")
			ui.printMsg("[SUM]   0.00-%.2f sec   %s  sender",
				durationSecs,
				cpsToString(uint64(float64(clientTotalCps)/durationSecs)))
			ui.printMsg("[SUM]   0.00-%.2f sec   %s  receiver",
				durationSecs,
				cpsToString(uint64(float64(serverTotalCps)/durationSecs)))
			return
		}

		// Get client-side totals for bandwidth/PPS tests
		clientTotalBw := atomic.LoadUint64(&test.testResult.totalBw)
		clientTotalPps := atomic.LoadUint64(&test.testResult.totalPps)
		serverTotalBw := test.ctrlResults.Bandwidth
		serverTotalPps := test.ctrlResults.Packets

		// Display iPerf3-style summary for bandwidth tests
		ui.printMsg("- - - - - - - - - - - - - - - - - - - - - - - - -")
		ui.printMsg("[ ID]   Interval        Transfer     Bitrate")

		// Sender line (client's transmitted data)
		ui.printMsg("[SUM]   0.00-%.2f sec   %s    %s  sender",
			durationSecs,
			bytesToString(clientTotalBw),
			bytesToRate(uint64(float64(clientTotalBw)/durationSecs)))

		// Receiver line (server's received data)
		ui.printMsg("[SUM]   0.00-%.2f sec   %s    %s  receiver",
			durationSecs,
			bytesToString(serverTotalBw),
			bytesToRate(uint64(float64(serverTotalBw)/durationSecs)))

		// For UDP tests, also show packet stats
		if test.testID.Protocol == UDP && (clientTotalPps > 0 || serverTotalPps > 0) {
			lostPkts := uint64(0)
			lostPct := 0.0
			if clientTotalPps > serverTotalPps {
				lostPkts = clientTotalPps - serverTotalPps
				lostPct = float64(lostPkts) / float64(clientTotalPps) * 100
			}
			ui.printMsg("")
			ui.printMsg("UDP Statistics:")
			ui.printMsg("  Sent:     %d packets", clientTotalPps)
			ui.printMsg("  Received: %d packets", serverTotalPps)
			ui.printMsg("  Lost:     %d packets (%.2f%%)", lostPkts, lostPct)
		}
	} else {
		ui.printDbg("Failed to receive results from server. Type=%v, CtrlResults=%v", ethrMsg.Type, ethrMsg.CtrlResults)
	}
}

func runTCPBandwidthTestHandler(test *ethrTest, conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()
	ec := test.newConn(conn)
	rserver, rport, _ := net.SplitHostPort(conn.RemoteAddr().String())
	lserver, lport, _ := net.SplitHostPort(conn.LocalAddr().String())
	ui.printMsg("[%3d] local %s port %s connected to %s port %s",
		ec.fd, lserver, lport, rserver, rport)
	size := test.clientParam.BufferSize
	buff := make([]byte, size)
	for i := uint32(0); i < size; i++ {
		buff[i] = byte(i)
	}
	bufferLen := len(buff)
	totalBytesToSend := test.clientParam.BwRate
	sentBytes := uint64(0)
	start, waitTime, bytesToSend := beginThrottle(totalBytesToSend, bufferLen)
ExitForLoop:
	for {
		select {
		case <-test.done:
			break ExitForLoop
		default:
			n := 0
			var err error
			if test.clientParam.Reverse {
				n, err = conn.Read(buff)
			} else {
				n, err = conn.Write(buff[:bytesToSend])
			}
			if err != nil {
				ui.printDbg("Error sending/receiving data on a connection for bandwidth test: %v", err)
				break ExitForLoop
			}
			atomic.AddUint64(&ec.bw, uint64(n))
			atomic.AddUint64(&test.testResult.bw, uint64(n))
			atomic.AddUint64(&test.testResult.totalBw, uint64(n))
			if !test.clientParam.Reverse {
				sentBytes += uint64(n)
				start, waitTime, sentBytes, bytesToSend = enforceThrottle(start, waitTime, totalBytesToSend, sentBytes, bufferLen)
			}
		}
	}
}

func runTCPLatencyTest(test *ethrTest, g time.Duration, toStop chan int) {
	ui.printMsg("Running latency test: %v, %v", test.clientParam.RttCount, test.clientParam.BufferSize)
	conn, err := ethrDial(TCP, test.dialAddr)
	if err != nil {
		ui.printErr("Error dialing the latency connection: %v", err)
		return
	}
	defer conn.Close()
	err = handshakeWithServer(test, conn)
	if err != nil {
		ui.printErr("Failed in handshake with the server. Error: %v", err)
		return
	}
	ui.emitLatencyHdr()
	buffSize := test.clientParam.BufferSize
	buff := make([]byte, buffSize)
	for i := uint32(0); i < buffSize; i++ {
		buff[i] = byte(i)
	}
	blen := len(buff)
	rttCount := test.clientParam.RttCount
	latencyNumbers := make([]time.Duration, rttCount)
ExitForLoop:
	for {
	ExitSelect:
		select {
		case <-test.done:
			break ExitForLoop
		default:
			t0 := time.Now()
			for i := uint32(0); i < rttCount; i++ {
				s1 := time.Now()
				n, err := conn.Write(buff)
				if err != nil || n < blen {
					ui.printDbg("Error sending/receiving data on a connection for latency test: %v", err)
					toStop <- disconnect
					break ExitSelect
				}
				_, err = io.ReadFull(conn, buff)
				if err != nil {
					ui.printDbg("Error sending/receiving data on a connection for latency test: %v", err)
					toStop <- disconnect
					break ExitSelect
				}
				e2 := time.Since(s1)
				latencyNumbers[i] = e2
			}
			// TODO temp code, fix it better, this is to allow server to do
			// server side latency measurements as well.
			_, _ = conn.Write(buff)
			calcAndPrintLatency(test, rttCount, latencyNumbers)
			t1 := time.Since(t0)
			if t1 < g {
				time.Sleep(g - t1)
			}
		}
	}
}

func calcAndPrintLatency(test *ethrTest, rttCount uint32, latencyNumbers []time.Duration) {
	sum := int64(0)
	for _, d := range latencyNumbers {
		sum += d.Nanoseconds()
	}
	elapsed := time.Duration(sum / int64(rttCount))
	sort.SliceStable(latencyNumbers, func(i, j int) bool {
		return latencyNumbers[i] < latencyNumbers[j]
	})
	//
	// Special handling for rttCount == 1. This prevents negative index
	// in the latencyNumber index. The other option is to use
	// roundUpToZero() but that is more expensive.
	//
	rttCountFixed := rttCount
	if rttCountFixed == 1 {
		rttCountFixed = 2
	}
	avg := elapsed
	min := latencyNumbers[0]
	max := latencyNumbers[rttCount-1]
	p50 := latencyNumbers[((rttCountFixed*50)/100)-1]
	p90 := latencyNumbers[((rttCountFixed*90)/100)-1]
	p95 := latencyNumbers[((rttCountFixed*95)/100)-1]
	p99 := latencyNumbers[((rttCountFixed*99)/100)-1]
	p999 := latencyNumbers[uint64(((float64(rttCountFixed)*99.9)/100)-1)]
	p9999 := latencyNumbers[uint64(((float64(rttCountFixed)*99.99)/100)-1)]
	ui.emitLatencyResults(
		test.session.remoteIP,
		protoToString(test.testID.Protocol),
		avg, min, max, p50, p90, p95, p99, p999, p9999)
}

func tcpRunCpsTest(test *ethrTest) {
	for th := uint32(0); th < test.clientParam.NumThreads; th++ {
		go func(th uint32) {
		ExitForLoop:
			for {
				select {
				case <-test.done:
					break ExitForLoop
				default:
					conn, err := ethrDialAll(TCP, test.dialAddr)
					if err == nil {
						// For CPS tests, just connect and disconnect immediately
						// Don't send any data - this measures pure connection establishment rate
						atomic.AddUint64(&test.testResult.cps, 1)
						atomic.AddUint64(&test.testResult.totalCps, 1)
						tcpconn, ok := conn.(*net.TCPConn)
						if ok {
							_ = tcpconn.SetLinger(0)
						}
						conn.Close()
					} else {
						ui.printDbg("Unable to dial TCP connection to %s, error: %v", test.dialAddr, err)
					}
				}
			}
		}(th)
	}
}

// tcpRunCpsTestWithCtrl runs CPS test with a control channel for deterministic test end
func tcpRunCpsTestWithCtrl(test *ethrTest, toStop chan int, duration time.Duration) {
	// Phase 1: Establish control connection
	ctrlConn, err := ethrDial(TCP, test.dialAddr)
	if err != nil {
		ui.printErr("Error dialing control connection: %v", err)
		toStop <- disconnect
		return
	}
	test.ctrlConn = ctrlConn

	// Generate unique session ID
	sessionID := generateSessionID()
	test.sessionID = sessionID

	// Do handshake on control connection
	ethrMsg := createSynMsg(test.testID, test.clientParam)
	err = sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send SYN message on control channel. Error: %v", err)
		ctrlConn.Close()
		toStop <- disconnect
		return
	}

	ethrMsg = recvSessionMsg(ctrlConn)
	if ethrMsg.Type != EthrAck {
		ui.printErr("Failed to receive ACK message from server on control channel.")
		ctrlConn.Close()
		toStop <- disconnect
		return
	}

	// Send control start message with session ID to register this as a CPS test
	ethrMsg = createCtrlStartMsg(sessionID)
	err = sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send CtrlStart message. Error: %v", err)
		ctrlConn.Close()
		toStop <- disconnect
		return
	}

	// Do time sync handshake (simplified - CPS doesn't need precise nanosecond sync)
	sendTime := time.Now()
	ethrMsg = createSyncStartMsg()
	err = sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send SyncStart message on control channel. Error: %v", err)
		ctrlConn.Close()
		toStop <- disconnect
		return
	}

	ethrMsg = recvSessionMsg(ctrlConn)
	recvTime := time.Now()
	if ethrMsg.Type != EthrSyncReady {
		ui.printErr("Failed to receive SyncReady message from server.")
		ctrlConn.Close()
		toStop <- disconnect
		return
	}
	delayNs := ethrMsg.SyncReady.DelayNs
	rtt := recvTime.Sub(sendTime)
	rttNs := rtt.Nanoseconds()

	// Calculate start time
	var startTime time.Time
	if delayNs == 0 {
		// Single-client mode
		ethrMsg = createSyncGoMsg(rttNs)
		err = sendSessionMsg(ctrlConn, ethrMsg)
		if err != nil {
			ui.printErr("Failed to send SyncGo message. Error: %v", err)
			ctrlConn.Close()
			toStop <- disconnect
			return
		}
		startTime = time.Now()
	} else {
		// Multi-client mode
		oneWayLatency := rtt / 2
		adjustedDelay := time.Duration(delayNs) - oneWayLatency
		if adjustedDelay < 0 {
			adjustedDelay = 0
		}
		startTime = time.Now().Add(adjustedDelay)

		ethrMsg = createSyncGoMsg(rttNs)
		err = sendSessionMsg(ctrlConn, ethrMsg)
		if err != nil {
			ui.printErr("Failed to send SyncGo message. Error: %v", err)
			ctrlConn.Close()
			toStop <- disconnect
			return
		}
		waitUntilTime(startTime)
	}

	// Phase 2: Start CPS test workers at synchronized time
	test.startTime = startTime
	startStatsTimerAt(startTime)
	for th := uint32(0); th < test.clientParam.NumThreads; th++ {
		go func(th uint32) {
		ExitForLoop:
			for {
				select {
				case <-test.done:
					break ExitForLoop
				default:
					conn, err := ethrDialAll(TCP, test.dialAddr)
					if err == nil {
						atomic.AddUint64(&test.testResult.cps, 1)
						atomic.AddUint64(&test.testResult.totalCps, 1)
						tcpconn, ok := conn.(*net.TCPConn)
						if ok {
							_ = tcpconn.SetLinger(0)
						}
						conn.Close()
					} else {
						ui.printDbg("Unable to dial TCP connection to %s, error: %v", test.dialAddr, err)
					}
				}
			}
		}(th)
	}

	// Phase 3: Wait for duration, then signal test end via control channel
	if duration > 0 {
		time.Sleep(duration)

		// Request results from server before stopping
		requestServerResults(test, ctrlConn, duration)
		ctrlConn.Close()

		// Signal test completion - runTest() will close test.done
		toStop <- timeout
	}
}

func clientRunPingTest(test *ethrTest, g time.Duration, warmupCount uint32) {
	// TODO: Override NumThreads for now, fix it later to support parallel
	// threads.
	test.clientParam.NumThreads = 1
	for th := uint32(0); th < test.clientParam.NumThreads; th++ {
		go func() {
			var sent, rcvd, lost uint32
			warmupText := "[warmup] "
			latencyNumbers := make([]time.Duration, 0)
		ExitForLoop:
			for {
				select {
				case <-test.done:
					printConnectionLatencyResults(test.dialAddr, test, sent, rcvd, lost, latencyNumbers)
					break ExitForLoop
				default:
					t0 := time.Now()
					if warmupCount > 0 {
						warmupCount--
						_, _ = clientRunPing(test, warmupText)
					} else {
						sent++
						latency, err := clientRunPing(test, "")
						if err == nil {
							rcvd++
							latencyNumbers = append(latencyNumbers, latency)
						} else {
							lost++
						}
					}
					if rcvd >= 1000 {
						printConnectionLatencyResults(test.dialAddr, test, sent, rcvd, lost, latencyNumbers)
						latencyNumbers = make([]time.Duration, 0)
						sent, rcvd, lost = 0, 0, 0
					}
					t1 := time.Since(t0)
					if t1 < g {
						time.Sleep(g - t1)
					}
				}
			}
		}()
	}
}

func clientRunPing(test *ethrTest, prefix string) (time.Duration, error) {
	if test.testID.Protocol == TCP {
		return tcpRunPing(test, prefix)
	} else {
		return icmpRunPing(test, prefix)
	}
}

func tcpRunPing(test *ethrTest, prefix string) (timeTaken time.Duration, err error) {
	t0 := time.Now()
	conn, err := ethrDial(TCP, test.dialAddr)
	if err != nil {
		ui.printMsg("[tcp] %sConnection to %s: Timed out (%v)", prefix, test.dialAddr, err)
		// Send failed ping to hub callback
		if hubPingCallback != nil && hubActiveTest != nil && prefix == "" {
			hubPingCallback("", test.dialAddr, TCP, 0, err, hubActiveTest)
		}
		return
	}
	timeTaken = time.Since(t0)
	rserver, rport, _ := net.SplitHostPort(conn.RemoteAddr().String())
	lserver, lport, _ := net.SplitHostPort(conn.LocalAddr().String())
	localAddr := fmt.Sprintf("[%s]:%s", lserver, lport)
	remoteAddr := fmt.Sprintf("[%s]:%s", rserver, rport)
	ui.printMsg("[tcp] %sConnection from %s to %s, Time: %s",
		prefix, localAddr, remoteAddr, durationToString(timeTaken))

	// Send successful ping to hub callback (only for non-warmup pings)
	if hubPingCallback != nil && hubActiveTest != nil && prefix == "" {
		hubPingCallback(localAddr, remoteAddr, TCP, timeTaken, nil, hubActiveTest)
	}

	tcpconn, ok := conn.(*net.TCPConn)
	if ok {
		_ = tcpconn.SetLinger(0)
	}
	conn.Close()
	return
}

func printConnectionLatencyResults(server string, test *ethrTest, sent, rcvd, lost uint32, latencyNumbers []time.Duration) {
	fmt.Println("-----------------------------------------------------------------------------------------")
	ui.printMsg("TCP connect statistics for %s:", server)
	ui.printMsg("  Sent = %d, Received = %d, Lost = %d", sent, rcvd, lost)

	// Send ping summary to hub callback (includes latency numbers for stats)
	if hubPingSummaryCallback != nil && hubActiveTest != nil {
		hubPingSummaryCallback(sent, rcvd, lost, latencyNumbers, hubActiveTest)
	}

	if rcvd > 0 {
		ui.emitLatencyHdr()
		calcAndPrintLatency(test, rcvd, latencyNumbers)
		fmt.Println("-----------------------------------------------------------------------------------------")
	}
}

func tcpRunTraceRoute(test *ethrTest, gap time.Duration, toStop chan int) {
	tcpRunTraceRouteInternal(test, gap, toStop, false)
}

func tcpRunMyTraceRoute(test *ethrTest, gap time.Duration, toStop chan int) {
	tcpRunTraceRouteInternal(test, gap, toStop, true)
}

func tcpRunTraceRouteInternal(test *ethrTest, gap time.Duration, toStop chan int, mtrMode bool) {
	gHop = make([]ethrHopData, gMaxHops)
	err := tcpDiscoverHops(test, mtrMode)
	if err != nil {
		ui.printErr("Destination %s is not responding to TCP connection.", test.session.remoteIP)
		ui.printErr("Terminating tracing...")
		toStop <- interrupt
		return
	}
	if !mtrMode {
		toStop <- done
		return
	}
	for i := 0; i < gCurHops; i++ {
		if gHop[i].addr != "" {
			go tcpProbeHop(test, gap, i)
		}
	}
}

func tcpProbeHop(test *ethrTest, gap time.Duration, hop int) {
	seq := 0
ExitForLoop:
	for {
		select {
		case <-test.done:
			break ExitForLoop
		default:
			t0 := time.Now()
			_, _ = tcpProbe(test, hop+1, gHop[hop].addr, &gHop[hop])
			seq++
			t1 := time.Since(t0)
			if t1 < gap {
				time.Sleep(gap - t1)
			}
		}
	}
}

func tcpDiscoverHops(test *ethrTest, mtrMode bool) error {
	ui.printMsg("Tracing route to %s over %d hops:", test.session.remoteIP, gMaxHops)
	for i := 0; i < gMaxHops; i++ {
		var hopData ethrHopData
		err, isLast := tcpProbe(test, i+1, "", &hopData)
		if err == nil {
			hopData.name, hopData.fullName = lookupHopName(hopData.addr)
		}
		if hopData.addr != "" {
			if mtrMode {
				ui.printMsg("%2d.|--%s", i+1, hopData.addr+" ["+hopData.fullName+"]")
			} else {
				ui.printMsg("%2d.|--%-70s %s", i+1, hopData.addr+" ["+hopData.fullName+"]", durationToString(hopData.last))
			}
		} else {
			ui.printMsg("%2d.|--%s", i+1, "???")
		}
		copyInitialHopData(i, hopData)
		if isLast {
			gCurHops = i + 1
			return nil
		}
	}
	return os.ErrNotExist
}

func tcpProbe(test *ethrTest, hop int, hopIP string, hopData *ethrHopData) (error, bool) {
	isLast := false
	c, err := IcmpNewConn(test.remoteIP)
	if err != nil {
		ui.printErr("Failed to create ICMP connection. Error: %v", err)
		return err, isLast
	}
	defer c.Close()
	localPortNum := uint16(8888)
	if gClientPort != 0 {
		localPortNum = gClientPort
	}
	localPortNum += uint16(hop)
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:], localPortNum)
	remotePortNum, _ := strconv.ParseUint(test.remotePort, 10, 16)
	binary.BigEndian.PutUint16(b[2:], uint16(remotePortNum))
	peerAddrChan := make(chan string)
	endTimeChan := make(chan time.Time)
	go func() {
		// Use shorter timeout for TCP traceroute - ICMP TTL exceeded should arrive quickly
		peerAddr, _, _ := icmpRecvMsg(c, TCP, time.Millisecond*500, hopIP, b, nil, 0)
		endTimeChan <- time.Now()
		peerAddrChan <- peerAddr
	}()
	startTime := time.Now()
	conn, err := ethrDialEx(TCP, test.dialAddr, gLocalIP, localPortNum, hop, int(gTOS))
	if err != nil {
		ui.printDbg("Failed to Dial the connection. Error: %v", err)
	} else {
		conn.Close()
	}
	hopData.sent++
	peerAddr := ""
	endTime := time.Now()
	if err == nil {
		isLast = true
		peerAddr = test.remoteIP
	} else {
		endTime = <-endTimeChan
		peerAddr = <-peerAddrChan
	}
	elapsed := endTime.Sub(startTime)
	if peerAddr == "" || (hopIP != "" && peerAddr != hopIP) {
		hopData.lost++
		ui.printDbg("Neither connection completed, nor ICMP TTL exceeded received.")
		return os.ErrNotExist, isLast
	}
	genHopData(hopData, peerAddr, elapsed)
	return nil, isLast
}

type ethrHopData struct {
	addr     string
	sent     uint32
	rcvd     uint32
	lost     uint32
	last     time.Duration
	best     time.Duration
	worst    time.Duration
	total    time.Duration
	name     string
	fullName string
}

var gMaxHops int = 30
var gCurHops int
var gHop []ethrHopData

func icmpRunPing(test *ethrTest, prefix string) (time.Duration, error) {
	dstIPAddr, _, err := ethrLookupIP(test.dialAddr)
	if err != nil {
		return time.Second, err
	}

	var hopData ethrHopData
	err, isLast := icmpProbe(test, dstIPAddr, time.Second, "", &hopData, 254, 255)
	if err != nil {
		ui.printMsg("[icmp] %sPing to %s: %v", prefix, test.dialAddr, err)
		// Send failed ping to hub callback
		if hubPingCallback != nil && hubActiveTest != nil && prefix == "" {
			hubPingCallback("", test.dialAddr, ICMP, 0, err, hubActiveTest)
		}
		return time.Second, err
	}
	if !isLast {
		ui.printMsg("[icmp] %sPing to %s: %s",
			prefix, test.dialAddr, "Non-EchoReply Received.")
		// Send failed ping to hub callback
		if hubPingCallback != nil && hubActiveTest != nil && prefix == "" {
			hubPingCallback("", test.dialAddr, ICMP, 0, os.ErrNotExist, hubActiveTest)
		}
		return time.Second, os.ErrNotExist
	}
	ui.printMsg("[icmp] %sPing to %s: %s",
		prefix, test.dialAddr, durationToString(hopData.last))

	// Send successful ping to hub callback (only for non-warmup pings)
	if hubPingCallback != nil && hubActiveTest != nil && prefix == "" {
		hubPingCallback("", test.dialAddr, ICMP, hopData.last, nil, hubActiveTest)
	}

	return hopData.last, nil
}

func icmpRunTraceRoute(test *ethrTest, gap time.Duration, toStop chan int) {
	icmpRunTraceRouteInternal(test, gap, toStop, false)
}

func icmpRunMyTraceRoute(test *ethrTest, gap time.Duration, toStop chan int) {
	icmpRunTraceRouteInternal(test, gap, toStop, true)
}

func icmpRunTraceRouteInternal(test *ethrTest, gap time.Duration, toStop chan int, mtrMode bool) {
	gHop = make([]ethrHopData, gMaxHops)
	dstIPAddr, _, err := ethrLookupIP(test.session.remoteIP)
	if err != nil {
		toStop <- interrupt
		return
	}
	err = icmpDiscoverHops(test, dstIPAddr, mtrMode)
	if err != nil {
		ui.printErr("Destination %s is not responding to ICMP Echo.", test.session.remoteIP)
		ui.printErr("Terminating tracing...")
		toStop <- interrupt
		return
	}
	if !mtrMode {
		toStop <- done
		return
	}
	for i := 0; i < gCurHops; i++ {
		if gHop[i].addr != "" {
			go icmpProbeHop(test, gap, i, dstIPAddr)
		}
	}
}

func copyInitialHopData(hop int, hopData ethrHopData) {
	gHop[hop].addr = hopData.addr
	gHop[hop].best = hopData.last
	gHop[hop].name = hopData.name
	gHop[hop].fullName = hopData.fullName
}

func genHopData(hopData *ethrHopData, peerAddr string, elapsed time.Duration) {
	hopData.addr = peerAddr
	hopData.last = elapsed
	if hopData.best > elapsed {
		hopData.best = elapsed
	}
	if hopData.worst < elapsed {
		hopData.worst = elapsed
	}
	hopData.total += elapsed
	hopData.rcvd++
}

func lookupHopName(addr string) (string, string) {
	name := ""
	tname := ""
	if addr == "" {
		return tname, name
	}
	names, err := net.LookupAddr(addr)
	if err == nil && len(names) > 0 {
		name = names[0]
		sz := len(name)

		if sz > 0 && name[sz-1] == '.' {
			name = name[:sz-1]
		}
		tname = truncateStringFromEnd(name, 16)
	}
	return tname, name
}

func icmpDiscoverHops(test *ethrTest, dstIPAddr net.IPAddr, mtrMode bool) error {
	if test.session.remoteIP == dstIPAddr.String() {
		ui.printMsg("Tracing route to %s over %d hops:", test.session.remoteIP, gMaxHops)
	} else {
		ui.printMsg("Tracing route to %s (%s) over %d hops:", test.session.remoteIP, dstIPAddr.String(), gMaxHops)
	}
	for i := 0; i < gMaxHops; i++ {
		var hopData ethrHopData
		// First try Windows ICMP API (works without admin on Windows)
		peerAddr, rttMs, isLast, winErr := WinIcmpProbe(dstIPAddr.String(), i+1, 2000)
		if winErr == nil {
			// Windows API succeeded
			if peerAddr != "" && peerAddr != "0.0.0.0" {
				hopData.addr = peerAddr
				hopData.last = time.Duration(rttMs) * time.Millisecond
				hopData.sent = 1
				hopData.rcvd = 1
			} else {
				hopData.sent = 1
				hopData.lost = 1
			}
		} else {
			// Fall back to raw socket method (for non-Windows or if Windows API fails)
			_, isLast = icmpProbe(test, dstIPAddr, time.Second*2, "", &hopData, i, 1)
		}
		if hopData.addr != "" {
			hopData.name, hopData.fullName = lookupHopName(hopData.addr)
		}
		if hopData.addr != "" {
			if mtrMode {
				ui.printMsg("%2d.|--%s", i+1, hopData.addr+" ["+hopData.fullName+"]")
			} else {
				ui.printMsg("%2d.|--%-70s %s", i+1, hopData.addr+" ["+hopData.fullName+"]", durationToString(hopData.last))
			}
		} else {
			ui.printMsg("%2d.|--%s", i+1, "???")
		}
		copyInitialHopData(i, hopData)
		if isLast {
			gCurHops = i + 1
			return nil
		}
	}
	return os.ErrNotExist
}

func icmpProbeHop(test *ethrTest, gap time.Duration, hop int, dstIPAddr net.IPAddr) {
	seq := 0
ExitForLoop:
	for {
		select {
		case <-test.done:
			break ExitForLoop
		default:
			t0 := time.Now()
			_, _ = icmpProbe(test, dstIPAddr, time.Second, gHop[hop].addr, &gHop[hop], hop, seq)
			seq++
			t1 := time.Since(t0)
			if t1 < gap {
				time.Sleep(gap - t1)
			}
		}
	}
}

func icmpProbe(test *ethrTest, dstIPAddr net.IPAddr, icmpTimeout time.Duration, hopIP string, hopData *ethrHopData, hop, seq int) (error, bool) {
	isLast := false
	echoMsg := fmt.Sprintf("Hello: Ethr - %v", hop)

	c, err := IcmpNewConn(test.remoteIP)
	if err != nil {
		ui.printErr("Failed to create ICMP connection. Error: %v", err)
		return err, isLast
	}
	defer c.Close()
	start, wb, err := icmpSendMsg(c, dstIPAddr, hop, seq, echoMsg, icmpTimeout)
	if err != nil {
		return err, isLast
	}
	hopData.sent++
	neededSeq := hop<<8 | seq
	peerAddr, isLast, err := icmpRecvMsg(c, ICMP, icmpTimeout, hopIP, wb[4:8], []byte(echoMsg), neededSeq)
	if err != nil {
		hopData.lost++
		ui.printDbg("Failed to receive ICMP reply packet. Error: %v", err)
		return err, isLast
	}
	elapsed := time.Since(start)
	genHopData(hopData, peerAddr, elapsed)
	return nil, isLast
}

func icmpSetTTL(c net.PacketConn, ttl int) error {
	switch gIPVersion {
	case ethrIPv4:
		return ipv4.NewPacketConn(c).SetTTL(ttl)
	case ethrIPv6:
		return ipv6.NewPacketConn(c).SetHopLimit(ttl)
	default:
		return os.ErrInvalid
	}
}

func icmpSetTOS(c net.PacketConn, tos int) error {
	if tos == 0 {
		return nil
	}
	switch gIPVersion {
	case ethrIPv4:
		return ipv4.NewPacketConn(c).SetTOS(tos)
	case ethrIPv6:
		return ipv6.NewPacketConn(c).SetTrafficClass(tos)
	default:
		return os.ErrInvalid
	}
}

func icmpSendMsg(c net.PacketConn, dstIPAddr net.IPAddr, hop, seq int, body string, timeout time.Duration) (time.Time, []byte, error) {
	start := time.Now()
	err := icmpSetTTL(c, hop+1)
	if err != nil {
		ui.printErr("Failed to set TTL. Error: %v", err)
		return start, nil, err
	}
	_ = icmpSetTOS(c, int(gTOS))

	err = c.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		ui.printErr("Failed to set Deadline. Error: %v", err)
		return start, nil, err
	}

	pid := 9999
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: pid, Seq: hop<<8 | seq,
			Data: []byte(body),
		},
	}
	if gIPVersion == ethrIPv6 {
		wm.Type = ipv6.ICMPTypeEchoRequest
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		ui.printErr("Failed to Marshal data. Error: %v", err)
		return start, nil, err
	}
	start = time.Now()
	if _, err := c.WriteTo(wb, &dstIPAddr); err != nil {
		ui.printErr("Failed to send ICMP data. Error: %v", err)
		return start, nil, err
	}
	return start, wb, nil
}

func icmpRecvMsg(c net.PacketConn, proto EthrProtocol, timeout time.Duration, neededPeer string, neededSig []byte, neededIcmpBody []byte, neededIcmpSeq int) (string, bool, error) {
	peerAddr := ""
	isLast := false
	err := c.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		ui.printErr("Failed to set Deadline. Error: %v", err)
		return peerAddr, isLast, err
	}
	for {
		peerAddr = ""
		b := make([]byte, 1500)
		n, peer, err := c.ReadFrom(b)
		if err != nil {
			if proto == ICMP {
				// In case of non-ICMP TraceRoute, it is expected that no packet is received
				// in some case, e.g. when packet reach final hop and TCP connection establishes.
				ui.printDbg("Failed to receive ICMP packet. Error: %v", err)
			}
			return peerAddr, isLast, err
		}
		if n == 0 {
			continue
		}
		ui.printDbg("Packet:\n%s", hex.Dump(b[:n]))
		ui.printDbg("Finding Pattern\n%v", hex.Dump(neededSig[:4]))
		peerAddr = peer.String()
		if neededPeer != "" && peerAddr != neededPeer {
			ui.printDbg("Matching peer is not found.")
			continue
		}
		icmpMsg, err := icmp.ParseMessage(IcmpProto(), b[:n])
		if err != nil {
			ui.printDbg("Failed to parse ICMP message: %v", err)
			continue
		}
		if icmpMsg.Type == ipv4.ICMPTypeTimeExceeded || icmpMsg.Type == ipv6.ICMPTypeTimeExceeded {
			body := icmpMsg.Body.(*icmp.TimeExceeded).Data
			index := bytes.Index(body, neededSig[:4])
			if index > 0 {
				if proto == TCP {
					ui.printDbg("Found correct ICMP error message. PeerAddr: %v", peerAddr)
					return peerAddr, isLast, nil
				} else if proto == ICMP {
					if index < 4 {
						ui.printDbg("Incorrect length of ICMP message.")
						continue
					}
					innerIcmpMsg, _ := icmp.ParseMessage(IcmpProto(), body[index-4:])
					switch innerIcmpMsg.Body.(type) {
					case *icmp.Echo:
						seq := innerIcmpMsg.Body.(*icmp.Echo).Seq
						if seq == neededIcmpSeq {
							return peerAddr, isLast, nil
						}
					default:
						// Ignore as this is not the right ICMP packet.
						ui.printDbg("Unable to recognize packet.")
					}
				}
			} else {
				ui.printDbg("Pattern %v not found.", hex.Dump(neededSig[:4]))
			}
		}

		if proto == ICMP && (icmpMsg.Type == ipv4.ICMPTypeEchoReply || icmpMsg.Type == ipv6.ICMPTypeEchoReply) {
			echo := icmpMsg.Body.(*icmp.Echo)
			ethrUnused(echo)
			b, _ := icmpMsg.Body.Marshal(1)
			if string(b[4:]) != string(neededIcmpBody) {
				continue
			}
			isLast = true
			return peerAddr, isLast, nil
		}
	}
}

func runUDPBandwidthAndPpsTest(test *ethrTest) {
	// Warn about potential UDP fragmentation issues
	bufSize := test.clientParam.BufferSize
	if bufSize > 1400 {
		ui.printDbg("WARNING: UDP buffer size (%d bytes) exceeds typical MTU (1500 bytes).", bufSize)
		ui.printDbg("Large UDP packets may be fragmented and dropped, especially over virtual networks (WSL, VMs, VPNs).")
		ui.printDbg("If you see no traffic on the server, try reducing buffer size with: -l 1400 or smaller.")
	}

	for th := uint32(0); th < test.clientParam.NumThreads; th++ {
		go func(th uint32) {
			size := test.clientParam.BufferSize
			buff := make([]byte, size)
			conn, err := ethrDialInc(UDP, test.dialAddr, uint16(th))
			if err != nil {
				ui.printDbg("Unable to dial UDP, error: %v", err)
				return
			}
			defer conn.Close()
			ec := test.newConn(conn)
			rserver, rport, _ := net.SplitHostPort(conn.RemoteAddr().String())
			lserver, lport, _ := net.SplitHostPort(conn.LocalAddr().String())
			ui.printMsg("[%3d] local %s port %s connected to %s port %s",
				ec.fd, lserver, lport, rserver, rport)
			bufferLen := len(buff)
			totalBytesToSend := test.clientParam.BwRate
			sentBytes := uint64(0)
			start, waitTime, bytesToSend := beginThrottle(totalBytesToSend, bufferLen)
		ExitForLoop:
			for {
				select {
				case <-test.done:
					break ExitForLoop
				default:
					n, err := conn.Write(buff[:bytesToSend])
					if err != nil {
						ui.printDbg("%v", err)
						continue
					}
					if n < bytesToSend {
						ui.printDbg("Partial write: %d", n)
						continue
					}
					atomic.AddUint64(&ec.bw, uint64(n))
					atomic.AddUint64(&ec.pps, 1)
					atomic.AddUint64(&test.testResult.bw, uint64(n))
					atomic.AddUint64(&test.testResult.pps, 1)
					atomic.AddUint64(&test.testResult.totalBw, uint64(n))
					atomic.AddUint64(&test.testResult.totalPps, 1)
					if !test.clientParam.Reverse {
						sentBytes += uint64(n)
						start, waitTime, sentBytes, bytesToSend = enforceThrottle(start, waitTime, totalBytesToSend, sentBytes, bufferLen)
					}
				}
			}
		}(th)
	}
}

// runUDPBandwidthAndPpsTestWithCtrl runs UDP bandwidth/PPS test with control channel
// Control channel is especially important for UDP because:
// 1. UDP has no delivery guarantee - packets can be lost silently
// 2. Client has no idea how many packets actually arrived at server
// 3. Server's received bandwidth/PPS can be significantly different from client's sent rate
func runUDPBandwidthAndPpsTestWithCtrl(test *ethrTest, toStop chan int, duration time.Duration) {
	// Warn about potential UDP fragmentation issues
	bufSize := test.clientParam.BufferSize
	if bufSize > 1400 {
		ui.printDbg("WARNING: UDP buffer size (%d bytes) exceeds typical MTU (1500 bytes).", bufSize)
		ui.printDbg("Large UDP packets may be fragmented and dropped, especially over virtual networks (WSL, VMs, VPNs).")
		ui.printDbg("If you see no traffic on the server, try reducing buffer size with: -l 1400 or smaller.")
	}

	// Phase 1: Create UDP connections first so we know their source ports
	numThreads := test.clientParam.NumThreads
	udpConns := make([]net.Conn, 0, numThreads)
	udpPorts := make([]int, 0, numThreads)

	for th := uint32(0); th < numThreads; th++ {
		conn, err := ethrDialInc(UDP, test.dialAddr, uint16(th))
		if err != nil {
			ui.printDbg("Unable to dial UDP for thread %d, error: %v", th, err)
			// Clean up already created connections
			for _, c := range udpConns {
				c.Close()
			}
			toStop <- disconnect
			return
		}
		udpConns = append(udpConns, conn)

		// Extract local port
		_, lportStr, _ := net.SplitHostPort(conn.LocalAddr().String())
		var lport int
		_, _ = fmt.Sscanf(lportStr, "%d", &lport)
		udpPorts = append(udpPorts, lport)
	}

	ui.printDbg("Created %d UDP connections to %s with local ports: %v", len(udpPorts), test.dialAddr, udpPorts)

	// Phase 2: Establish TCP control connection
	ctrlConn, err := ethrDial(TCP, test.dialAddr)
	if err != nil {
		ui.printErr("Error dialing control connection: %v", err)
		for _, c := range udpConns {
			c.Close()
		}
		toStop <- disconnect
		return
	}
	test.ctrlConn = ctrlConn

	// Generate unique session ID
	sessionID := generateSessionID()
	test.sessionID = sessionID

	// Do handshake on control connection (TCP for reliability)
	ethrMsg := createSynMsg(test.testID, test.clientParam)
	err = sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send SYN message on control channel. Error: %v", err)
		ctrlConn.Close()
		for _, c := range udpConns {
			c.Close()
		}
		toStop <- disconnect
		return
	}

	ethrMsg = recvSessionMsg(ctrlConn)
	if ethrMsg.Type != EthrAck {
		ui.printErr("Failed to receive ACK message from server on control channel.")
		ctrlConn.Close()
		for _, c := range udpConns {
			c.Close()
		}
		toStop <- disconnect
		return
	}

	// Send control start message with session ID and UDP ports
	ethrMsg = createCtrlStartMsgWithPorts(sessionID, udpPorts)
	err = sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send CtrlStart message. Error: %v", err)
		ctrlConn.Close()
		for _, c := range udpConns {
			c.Close()
		}
		toStop <- disconnect
		return
	}

	// Do time sync handshake
	sendTime := time.Now()
	ethrMsg = createSyncStartMsg()
	err = sendSessionMsg(ctrlConn, ethrMsg)
	if err != nil {
		ui.printErr("Failed to send SyncStart message. Error: %v", err)
		ctrlConn.Close()
		for _, c := range udpConns {
			c.Close()
		}
		toStop <- disconnect
		return
	}

	ethrMsg = recvSessionMsg(ctrlConn)
	recvTime := time.Now()
	if ethrMsg.Type != EthrSyncReady {
		ui.printErr("Failed to receive SyncReady message from server.")
		ctrlConn.Close()
		for _, c := range udpConns {
			c.Close()
		}
		toStop <- disconnect
		return
	}
	delayNs := ethrMsg.SyncReady.DelayNs
	rtt := recvTime.Sub(sendTime)
	rttNs := rtt.Nanoseconds()

	var startTime time.Time
	if delayNs == 0 {
		ethrMsg = createSyncGoMsg(rttNs)
		_ = sendSessionMsg(ctrlConn, ethrMsg)
		startTime = time.Now()
	} else {
		oneWayLatency := rtt / 2
		adjustedDelay := time.Duration(delayNs) - oneWayLatency
		if adjustedDelay < 0 {
			adjustedDelay = 0
		}
		startTime = time.Now().Add(adjustedDelay)
		ethrMsg = createSyncGoMsg(rttNs)
		_ = sendSessionMsg(ctrlConn, ethrMsg)
		waitUntilTime(startTime)
	}

	// Phase 3: Start UDP data transfer using pre-created connections
	test.startTime = startTime
	startStatsTimerAt(startTime)

	// Run UDP test with pre-created connections
	runUDPBandwidthWithConns(test, udpConns)

	// Wait for duration, then request results BEFORE signaling test completion
	// If duration is 0, run forever (only stop on interrupt)
	if duration > 0 {
		go func() {
			// Wait for the test duration
			time.Sleep(duration)
			// Small extra delay to ensure server has received final packets
			time.Sleep(200 * time.Millisecond)
			// Request results from server
			requestServerResults(test, ctrlConn, duration)
			ctrlConn.Close()
			// Now signal that test should stop
			toStop <- timeout
		}()
	}
}

// runUDPBandwidthWithConns runs UDP bandwidth test with pre-created connections
func runUDPBandwidthWithConns(test *ethrTest, conns []net.Conn) {
	for th, conn := range conns {
		go func(th int, conn net.Conn) {
			defer conn.Close()
			size := test.clientParam.BufferSize
			buff := make([]byte, size)
			ec := test.newConn(conn)
			rserver, rport, _ := net.SplitHostPort(conn.RemoteAddr().String())
			lserver, lport, _ := net.SplitHostPort(conn.LocalAddr().String())
			ui.printMsg("[%3d] local %s port %s connected to %s port %s",
				ec.fd, lserver, lport, rserver, rport)
			bufferLen := len(buff)
			totalBytesToSend := test.clientParam.BwRate
			sentBytes := uint64(0)
			start, waitTime, bytesToSend := beginThrottle(totalBytesToSend, bufferLen)
		ExitForLoop:
			for {
				select {
				case <-test.done:
					break ExitForLoop
				default:
					n, err := conn.Write(buff[:bytesToSend])
					if err != nil {
						ui.printDbg("UDP Write error: %v", err)
						continue
					}
					if n < bytesToSend {
						ui.printDbg("Partial write: %d", n)
						continue
					}
					atomic.AddUint64(&ec.bw, uint64(n))
					atomic.AddUint64(&ec.pps, 1)
					atomic.AddUint64(&test.testResult.bw, uint64(n))
					atomic.AddUint64(&test.testResult.pps, 1)
					atomic.AddUint64(&test.testResult.totalBw, uint64(n))
					atomic.AddUint64(&test.testResult.totalPps, 1)
					if !test.clientParam.Reverse {
						sentBytes += uint64(n)
						start, waitTime, sentBytes, bytesToSend = enforceThrottle(start, waitTime, totalBytesToSend, sentBytes, bufferLen)
					}
				}
			}
		}(th, conn)
	}
}
