// -----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
// -----------------------------------------------------------------------------
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var gServerCancelChan chan struct{} // Channel to signal server shutdown
var gUDPListener *net.UDPConn       // UDP listener for cleanup on shutdown

// Per-session stats for multi-client support
// Each client gets a unique sessionID, and we track stats independently
type sessionStats struct {
	sessionID  string
	remoteIP   string
	totalBw    uint64 // Total bytes received
	totalPps   uint64 // Total packets received
	bw         uint64 // Current interval bandwidth (for display)
	pps        uint64 // Current interval packets (for display)
	udpPorts   []int  // UDP source ports for this session
	lastAccess time.Time
}

// Global registry mapping sessionID -> sessionStats
var gSessionStats = make(map[string]*sessionStats)
var gSessionStatsLock sync.RWMutex

// Global registry mapping "ip:port" -> sessionID for UDP packet lookup
var gUDPPortToSession = make(map[string]string)
var gUDPPortToSessionLock sync.RWMutex

// Global registry mapping port-only -> sessionID for NAT scenarios (e.g., WSL2)
// where TCP and UDP may show different source IPs
var gUDPPortOnlyToSession = make(map[int]string)
var gUDPPortOnlyToSessionLock sync.RWMutex

// registerSessionStats registers a new session with its UDP ports
func registerSessionStats(sessionID string, remoteIP string, udpPorts []int) *sessionStats {
	gSessionStatsLock.Lock()
	defer gSessionStatsLock.Unlock()

	stats := &sessionStats{
		sessionID:  sessionID,
		remoteIP:   remoteIP,
		udpPorts:   udpPorts,
		lastAccess: time.Now(),
	}
	gSessionStats[sessionID] = stats

	// Register UDP port mappings (both IP:port and port-only for NAT scenarios)
	gUDPPortToSessionLock.Lock()
	for _, port := range udpPorts {
		key := fmt.Sprintf("%s:%d", remoteIP, port)
		gUDPPortToSession[key] = sessionID
		ui.printDbg("Registered UDP port mapping: %s -> session %s", key, sessionID)
	}
	gUDPPortToSessionLock.Unlock()

	// Also register port-only mappings for NAT scenarios (e.g., WSL2 -> Windows)
	// where UDP packets may arrive from a different IP than the TCP control channel
	gUDPPortOnlyToSessionLock.Lock()
	for _, port := range udpPorts {
		gUDPPortOnlyToSession[port] = sessionID
		ui.printDbg("Registered UDP port-only mapping: %d -> session %s", port, sessionID)
	}
	gUDPPortOnlyToSessionLock.Unlock()

	ui.printDbg("Registered session %s from %s with %d UDP ports", sessionID, remoteIP, len(udpPorts))
	return stats
}

// getSessionStatsByID looks up session stats by sessionID
func getSessionStatsByID(sessionID string) *sessionStats {
	gSessionStatsLock.RLock()
	defer gSessionStatsLock.RUnlock()
	return gSessionStats[sessionID]
}

// getSessionStatsByUDPAddr looks up session stats by UDP source address (ip:port)
// Falls back to port-only lookup for NAT scenarios (e.g., WSL2 -> Windows)
func getSessionStatsByUDPAddr(remoteAddr string, port int) *sessionStats {
	// First try exact IP:port match
	gUDPPortToSessionLock.RLock()
	sessionID, found := gUDPPortToSession[remoteAddr]
	gUDPPortToSessionLock.RUnlock()

	if found {
		return getSessionStatsByID(sessionID)
	}

	// Fall back to port-only lookup for NAT scenarios
	gUDPPortOnlyToSessionLock.RLock()
	sessionID, found = gUDPPortOnlyToSession[port]
	gUDPPortOnlyToSessionLock.RUnlock()

	if found {
		return getSessionStatsByID(sessionID)
	}

	return nil
}

// unregisterSessionStats removes a session and its port mappings
func unregisterSessionStats(sessionID string) {
	gSessionStatsLock.Lock()
	stats, found := gSessionStats[sessionID]
	if found {
		delete(gSessionStats, sessionID)
	}
	gSessionStatsLock.Unlock()

	if found && stats != nil {
		gUDPPortToSessionLock.Lock()
		for _, port := range stats.udpPorts {
			key := fmt.Sprintf("%s:%d", stats.remoteIP, port)
			delete(gUDPPortToSession, key)
		}
		gUDPPortToSessionLock.Unlock()

		gUDPPortOnlyToSessionLock.Lock()
		for _, port := range stats.udpPorts {
			delete(gUDPPortOnlyToSession, port)
		}
		gUDPPortOnlyToSessionLock.Unlock()
		ui.printDbg("Unregistered session %s", sessionID)
	}
}

func initServer(showUI bool) {
	initServerUI(showUI)
}

func finiServer() {
	// Close UDP listener if it's open
	if gUDPListener != nil {
		ui.printDbg("Closing UDP listener on port %d", gEthrPort)
		err := gUDPListener.Close()
		if err != nil {
			ui.printDbg("Error closing UDP listener: %v", err)
		} else {
			ui.printDbg("UDP listener closed successfully")
		}
		gUDPListener = nil
		// Give OS time to release the port
		time.Sleep(100 * time.Millisecond)
	} else {
		ui.printDbg("UDP listener is nil, nothing to close")
	}
	ui.fini()
	logFini()
}

func showAcceptedIPVersion() {
	var ipVerString string
	switch gIPVersion {
	case ethrIPv4:
		ipVerString = "ipv4"
	case ethrIPv6:
		ipVerString = "ipv6"
	default:
		ipVerString = "ipv4, ipv6"
	}
	ui.printMsg("Accepting IP version: %s", ipVerString)
}

var gOneClient bool

func runServer(serverParam ethrServerParam) error {
	// Initialize cancel channel
	gServerCancelChan = make(chan struct{})
	defer func() {
		gServerCancelChan = nil
	}()

	gOneClient = serverParam.oneClient
	defer stopStatsTimer()
	initServer(serverParam.showUI)
	if !gOneClient {
		// In multi-client mode, start stats timer immediately
		startStatsTimer()
	}
	fmt.Println("-----------------------------------------------------------")
	showAcceptedIPVersion()
	if gOneClient {
		ui.printMsg("Running in single-client mode (one-off)")
	}
	ui.printMsg("Listening on port %d for TCP & UDP", gEthrPort)

	// Start UDP server (returns immediately after starting goroutines, or error if can't bind)
	err := srvrRunUDPServer()
	if err != nil {
		finiServer()
		fmt.Printf("Error running UDP server: %v\n", err)
		return fmt.Errorf("UDP server error: %w", err)
	}

	// Notify hub that server is ready and listening
	if hubServerReadyCallback != nil {
		hubServerReadyCallback(int(gEthrPort))
	}

	// Start TCP server in goroutine so we can monitor for cancellation
	tcpErrChan := make(chan error, 1)
	go func() {
		tcpErrChan <- srvrRunTCPServer()
	}()

	// Wait for either TCP server to fail or cancel signal
	select {
	case err := <-tcpErrChan:
		finiServer()
		fmt.Printf("Error running TCP server: %v\n", err)
		return fmt.Errorf("TCP server error: %w", err)
	case <-gServerCancelChan:
		// Immediately close UDP listener when cancelled
		if gUDPListener != nil {
			ui.printDbg("Closing UDP listener on port %d", gEthrPort)
			gUDPListener.Close()
		}
		finiServer()
		ui.printDbg("Server cancelled")
		return nil
	}
}

func handshakeWithClient(_ *ethrTest, conn net.Conn) (testID EthrTestID, clientParam EthrClientParam, sessionID string, err error) {
	ethrMsg := recvSessionMsg(conn)
	if ethrMsg.Type != EthrSyn {
		// No SYN received - likely a CPS test where client just connects/disconnects
		err = os.ErrInvalid
		return
	}
	testID = ethrMsg.Syn.TestID
	clientParam = ethrMsg.Syn.ClientParam
	sessionID = ethrMsg.Syn.SessionID
	ethrMsg = createAckMsg()
	err = sendSessionMsg(conn, ethrMsg)
	return
}

// syncStartWithClient synchronizes the start time for bandwidth tests
// The server tells the client when its next stats interval starts,
// and the client aligns to that timing.
// Returns: isControl=true if control channel mode, isInBandSync=true if in-band sync mode
func trySyncStartWithClient(test *ethrTest, conn net.Conn) (isControlChannel bool, sessionID string, err error) {
	// Set a short read deadline to detect the connection type
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	ethrMsg := recvSessionMsg(conn)
	_ = conn.SetReadDeadline(time.Time{}) // Clear deadline

	if ethrMsg.Type == EthrCtrlStart {
		// This is a control channel connection (iPerf-style)
		// Return session ID to caller - DON'T store in shared test object!
		if ethrMsg.CtrlStart != nil {
			sessionID = ethrMsg.CtrlStart.SessionID

			// Register session stats for this session (for both TCP and UDP)
			// This allows data connections to accumulate stats per session
			server, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			registerSessionStats(sessionID, server, ethrMsg.CtrlStart.UDPPorts)

			// Reset startTime if this is a new session (different sessionID)
			// This ensures each new test run behaves like a fresh start
			// For multi-threaded tests with same sessionID, we keep the existing startTime
			if test.sessionID != sessionID {
				test.startTime = time.Time{}
				test.sessionID = sessionID
				// Reset test stats for the new session
				atomic.StoreUint64(&test.testResult.bw, 0)
				atomic.StoreUint64(&test.testResult.pps, 0)
				atomic.StoreUint64(&test.testResult.cps, 0)
				atomic.StoreUint64(&test.testResult.totalBw, 0)
				atomic.StoreUint64(&test.testResult.totalPps, 0)
				atomic.StoreUint64(&test.testResult.totalCps, 0)
			}
		}
		test.ctrlConn = conn

		// Mark test as active (not dormant) since control channel test is starting
		test.isDormant = false

		isControlChannel = true

		// Now wait for sync start message
		ethrMsg = recvSessionMsg(conn)
		if ethrMsg.Type != EthrSyncStart {
			ui.printDbg("Failed to receive SyncStart message on control channel.")
			err = os.ErrInvalid
			return
		}
		// Do time sync (same as in-band mode)
		err = doTimeSync(test, conn)
		if err != nil {
			return
		}
		// Control channel stays open - caller must handle it
		// (either call handleControlChannel directly or in a goroutine)
		return
	}

	if ethrMsg.Type == EthrSyncStart {
		// In-band sync mode (-ncc on client): sync happens on data connection
		isControlChannel = false
		// For -ncc mode, always reset startTime since each test is independent
		// (no control channel to track sessionID across connections)
		test.startTime = time.Time{}
		err = doTimeSync(test, conn)
		return
	}

	// Not a sync connection - this is a pure data connection
	isControlChannel = false
	return
}

// doTimeSync performs the time synchronization handshake
func doTimeSync(test *ethrTest, conn net.Conn) (err error) {
	if gOneClient {
		// Single-client mode: 3-way handshake to measure RTT
		ethrMsg := createSyncReadyMsg(0)
		err = sendSessionMsg(conn, ethrMsg)
		if err != nil {
			ui.printDbg("Failed to send SyncReady message to client. Error: %v", err)
			return
		}

		ethrMsg = recvSessionMsg(conn)
		if ethrMsg.Type != EthrSyncGo {
			ui.printDbg("Failed to receive SyncGo message from client.")
			err = os.ErrInvalid
			return
		}
		rttNs := ethrMsg.SyncGo.RttNs

		halfRtt := time.Duration(rttNs / 2)
		time.Sleep(halfRtt)

		startTime := time.Now()
		test.startTime = startTime
		startStatsTimerAt(startTime)
	} else {
		// Multi-client mode: align to existing stats timer
		delayNs := getTimeToNextTick()

		ethrMsg := createSyncReadyMsg(delayNs)
		err = sendSessionMsg(conn, ethrMsg)
		if err != nil {
			ui.printDbg("Failed to send SyncReady message to client. Error: %v", err)
			return
		}

		ethrMsg = recvSessionMsg(conn)
		if ethrMsg.Type != EthrSyncGo {
			ui.printDbg("Failed to receive SyncGo message from client.")
			err = os.ErrInvalid
			return
		}

		time.Sleep(time.Duration(delayNs))
		startTime := time.Now()
		test.startTime = startTime
	}
	return
}

// handleControlChannel handles control channel messages (iPerf-style)
// This runs in a goroutine while the test is in progress
func handleControlChannel(test *ethrTest, sessionID string, conn net.Conn) {
	ui.printDbg("Control channel handler started for test: %v, sessionID: %s", test.testID, sessionID)

	// Clean up session stats when done
	defer func() {
		if sessionID != "" {
			unregisterSessionStats(sessionID)
		}
	}()

	for {
		ethrMsg := recvSessionMsg(conn)
		if ethrMsg.Type == EthrInv {
			// Connection closed or error - client disconnected unexpectedly
			ui.printDbg("Control channel: received invalid/closed connection, clearing control channel")
			// Only mark dormant if this is the last reference to the test
			// Other clients from the same IP might still be using it
			if atomic.LoadInt32(&test.refCount) <= 1 {
				test.isDormant = true
			}
			test.ctrlConn = nil // Clear control connection so cleanup goroutine can remove this test
			return
		}

		switch ethrMsg.Type {
		case EthrCtrlTestEnd:
			// Only mark test as dormant if this is the last reference
			// Other clients from the same IP might still have active tests
			if atomic.LoadInt32(&test.refCount) <= 1 {
				test.isDormant = true
			}
			test.ctrlConn = nil // Clear control connection for proper cleanup and next test

			// Client signals test end - send our cumulative results
			// For UDP with session tracking, use session stats; otherwise use test stats
			var totalBw, totalPps uint64
			sessionStats := getSessionStatsByID(sessionID)
			if sessionStats != nil {
				totalBw = atomic.LoadUint64(&sessionStats.totalBw)
				totalPps = atomic.LoadUint64(&sessionStats.totalPps)
				ui.printDbg("Control channel: using session stats - totalBw=%d, totalPps=%d", totalBw, totalPps)
			} else {
				totalBw = atomic.LoadUint64(&test.testResult.totalBw)
				totalPps = atomic.LoadUint64(&test.testResult.totalPps)
				ui.printDbg("Control channel: using test stats - totalBw=%d, totalPps=%d", totalBw, totalPps)
			}
			totalCps := atomic.LoadUint64(&test.testResult.totalCps)
			ui.printDbg("Control channel: sending results - totalBw=%d, totalCps=%d, totalPps=%d", totalBw, totalCps, totalPps)
			results := createCtrlResultsMsg(totalBw, totalCps, totalPps)
			err := sendSessionMsg(conn, results)
			if err != nil {
				ui.printDbg("Control channel: failed to send results: %v", err)
			}
			return
		default:
			ui.printDbg("Unexpected message type on control channel: %v", ethrMsg.Type)
		}
	}
}

func srvrRunTCPServer() error {
	l, err := net.Listen(Tcp(), gLocalIP+":"+gEthrPortStr)
	if err != nil {
		return err
	}
	defer l.Close()

	// Start a cleanup goroutine for idle TCP tests (similar to UDP)
	// This is needed for CPS tests where connection handlers don't sleep
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		for {
			select {
			case <-gServerCancelChan:
				return
			case <-time.After(500 * time.Millisecond):
				gSessionLock.Lock()
				for sessionKey, session := range gSessions {
					for testKey, test := range session.tests {
						// Skip tests with control channel - they use deterministic start/end signaling
						if test.ctrlConn != nil {
							continue
						}

						// Delete TCP tests that have been inactive for > 1.2 seconds
						// This handles cleanup for CPS tests with minimal extra output (non-control-channel mode only)
						if testKey.Protocol == TCP && time.Since(test.lastAccess) > (1200*time.Millisecond) {
							ui.printDbg("Cleaning up idle TCP test: %v", testKey)
							delete(session.tests, testKey)
							session.testCount--
							if session.testCount == 0 {
								delete(gSessions, sessionKey)
								deleteKey(sessionKey)
							}
						}
					}
				}
				gSessionLock.Unlock()
			}
		}
	}()

	// Use a channel to signal when Accept returns
	acceptChan := make(chan net.Conn)
	acceptErrChan := make(chan error, 1)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				acceptErrChan <- err
				return
			}
			acceptChan <- conn
		}
	}()

	for {
		select {
		case <-gServerCancelChan:
			l.Close()     // This will cause Accept to return with error
			<-cleanupDone // Wait for cleanup goroutine
			return nil
		case err := <-acceptErrChan:
			// Check if this is due to cancellation
			select {
			case <-gServerCancelChan:
				<-cleanupDone
				return nil
			default:
				ui.printErr("Error accepting new TCP connection: %v", err)
				return err
			}
		case conn := <-acceptChan:
			go srvrHandleNewTcpConn(conn)
		}
	}
}

func srvrHandleNewTcpConn(conn net.Conn) {
	defer conn.Close()

	server, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	ethrUnused(server, port)
	if err != nil {
		ui.printDbg("RemoteAddr: Split host port failed: %v", err)
		return
	}
	lserver, lport, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		ui.printDbg("LocalAddr: Split host port failed: %v", err)
		return
	}
	ethrUnused(lserver, lport)

	test, isNew := createOrGetTest(server, TCP, All)
	if test == nil {
		return
	}

	// Update last access time for proper cleanup
	test.lastAccess = time.Now()

	// Set a short timeout for handshake to detect CPS-only connections
	// CPS test clients just open and close connections without sending any data
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// First do the basic handshake to determine test type
	testID, clientParam, sessionID, err := handshakeWithClient(test, conn)
	if err != nil {
		// If handshake fails, this is a pure CPS test connection (no control channel - old style -ncc)
		// Increment CPS counters for this pure CPS connection
		atomic.AddUint64(&test.testResult.cps, 1)
		atomic.AddUint64(&test.testResult.totalCps, 1)
		// Activate the test if it's the first connection
		if isNew {
			test.isDormant = false
		}
		// Just count it and return immediately without sleeping
		// The test object remains alive to accumulate CPS stats
		// Test cleanup happens via the idle test cleanup mechanism
		return
	}

	// Update test object with actual test type from client
	// This allows proper reporting to hub/UI
	test.testID = testID
	test.clientParam = clientParam

	// This is NOT a pure CPS connection - it has a handshake
	// Use deferred deletion with sleep for proper test lifecycle management
	isCPSorPing := true
	defer func() {
		if isCPSorPing {
			time.Sleep(2 * time.Second)
		}
		safeDeleteTest(test)
	}()

	// Clear the deadline for subsequent operations
	_ = conn.SetReadDeadline(time.Time{})

	// Now we know this is NOT a pure CPS test - print connection info
	ui.printDbg("New connection from %v, port %v to %v, port %v", server, port, lserver, lport)
	if isNew {
		ui.emitTestHdr(test)
	}

	// Print client parameters received (only in debug mode)
	if clientParam.NumThreads > 0 || clientParam.BufferSize > 0 || clientParam.Duration > 0 {
		ui.printDbg("Client parameters - Threads: %d, BufferSize: %dKB, Duration: %ds, Reverse: %v, BwRate: %d",
			clientParam.NumThreads, clientParam.BufferSize/1024, int(clientParam.Duration.Seconds()),
			clientParam.Reverse, clientParam.BwRate)
	}

	isCPSorPing = false
	switch testID.Protocol {
	case TCP:
		switch testID.Type {
		case Bandwidth:
			// For bandwidth tests, try to do synchronization
			// Control connections send CtrlStart, in-band sync sends SyncStart, data connections send neither
			isCtrl, ctrlSessionID, err := trySyncStartWithClient(test, conn)
			if err != nil {
				ui.printDbg("Failed to synchronize start time with client. Error: %v", err)
				return
			}
			if isCtrl {
				// This is a control channel - reset cumulative totals for new test session
				atomic.StoreUint64(&test.testResult.totalBw, 0)
				atomic.StoreUint64(&test.testResult.totalPps, 0)
				// Notify hub about new client connection (for server mode UI)
				if hubNewClientCallback != nil {
					hubNewClientCallback(server, TCP, Bandwidth, test)
				}
				// Handle control protocol, don't run bandwidth test
				// handleControlChannel blocks until client sends test end
				// Pass the session ID directly - don't use test.sessionID which is shared
				handleControlChannel(test, ctrlSessionID, conn)
				return
			}
			// This is a data connection (or in-band sync first connection) - run bandwidth test
			// If sessionID is provided, accumulate stats to session for multi-client support
			srvrRunTCPBandwidthTestWithSession(test, clientParam, conn, sessionID)
		case Cps:
			// For CPS tests, check if this is a control channel
			isCtrl, ctrlSessionID, err := trySyncStartWithClient(test, conn)
			if err != nil {
				ui.printDbg("Failed to check for control channel. Error: %v", err)
				return
			}
			if isCtrl {
				// This is a control channel for CPS test - handle control protocol
				// Reset CPS counter for new test session
				atomic.StoreUint64(&test.testResult.cps, 0)
				// Notify hub about new client connection (for server mode UI)
				if hubNewClientCallback != nil {
					hubNewClientCallback(server, TCP, Cps, test)
				}
				handleControlChannel(test, ctrlSessionID, conn)
				return
			}
			// This shouldn't happen for CPS tests - connections without handshake are handled earlier
			ui.printDbg("Unexpected: CPS test with handshake but no control channel")
		case Latency:
			ui.emitLatencyHdr()
			srvrRunTCPLatencyTest(test, clientParam, conn)
		}
	case UDP:
		// This is a TCP control channel for UDP tests
		// UDP tests benefit greatly from control channel to report received bandwidth/PPS
		isCPSorPing = true // Use delayed deletion since UDP data comes separately

		// For multi-client support, we track UDP stats per client IP
		// The UDP packets will arrive from the same IP but possibly different ports
		// We use IP-only lookup since UDP "connection" uses a different source port than control channel
		udpTest, isNewUDP := createOrGetTest(server, UDP, All)
		if udpTest == nil {
			ui.printDbg("Failed to create UDP test for control channel")
			return
		}
		ui.printDbg("UDP control channel: got test (isNew=%v, isDormant=%v, sessionID=%s)",
			isNewUDP, udpTest.isDormant, udpTest.sessionID)

		// Update UDP test with actual test type and client parameters from handshake
		udpTest.testID = testID
		udpTest.clientParam = clientParam

		// For multi-client from same IP: DON'T reset totals here
		// Each client's stats are added to the shared test object
		// This means multi-client from same IP will see aggregate stats
		// TODO: For true per-client tracking, embed session ID in UDP packets

		isCtrl, udpSessionID, err := trySyncStartWithClient(udpTest, conn)
		ui.printDbg("UDP control channel: after trySyncStart (isCtrl=%v, isDormant=%v, err=%v)",
			isCtrl, udpTest.isDormant, err)
		if err != nil {
			ui.printDbg("Failed to synchronize start time with UDP test client. Error: %v", err)
			safeDeleteTest(udpTest)
			return
		}

		if isCtrl {
			// Notify hub about new client connection (for server mode UI)
			// Use the actual test type from testID (Pps or Bandwidth)
			if hubNewClientCallback != nil {
				hubNewClientCallback(server, UDP, testID.Type, udpTest)
			}
			// Control channel mode - handleControlChannel runs in this goroutine
			// to keep the connection open (defer conn.Close() would close it otherwise)
			handleControlChannel(udpTest, udpSessionID, conn)
		}
		// Note: The UDP test results will be available because srvrRunUDPPacketHandler
		// writes to the same test object
	}
}

// srvrRunTCPBandwidthTestWithSession runs TCP bandwidth test and accumulates stats
// If sessionID is provided (multi-client mode), stats are also accumulated to session stats
func srvrRunTCPBandwidthTestWithSession(test *ethrTest, clientParam EthrClientParam, conn net.Conn, sessionID string) {
	// Activate the test (mark as not dormant) when data connection starts
	// For control channel tests, this was already done in trySyncStartWithClient
	// For non-control channel tests (-ncc mode), we need to activate here
	test.isDormant = false

	// Look up session stats if sessionID is provided
	var sessStats *sessionStats
	if sessionID != "" {
		sessStats = getSessionStatsByID(sessionID)
		if sessStats == nil {
			ui.printDbg("TCP data connection has sessionID %s but no session stats found - creating one", sessionID)
			// Create session stats if not exists (shouldn't happen normally - control channel creates it)
			server, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			sessStats = registerSessionStats(sessionID, server, nil)
		}
	}

	size := clientParam.BufferSize
	buff := make([]byte, size)
	for i := uint32(0); i < size; i++ {
		buff[i] = byte(i)
	}
	bufferLen := len(buff)
	totalBytesToSend := test.clientParam.BwRate
	sentBytes := uint64(0)
	start, waitTime, bytesToSend := beginThrottle(totalBytesToSend, bufferLen)

	// Update lastAccess periodically to prevent cleanup goroutine from marking test dormant
	lastAccessUpdate := time.Now()

	for {
		n := 0
		var err error
		if clientParam.Reverse {
			n, err = conn.Write(buff[:bytesToSend])
		} else {
			n, err = conn.Read(buff)
		}
		if err != nil {
			ui.printDbg("Error sending/receiving data on a connection for bandwidth test: %v", err)
			break
		}
		// Always update test stats (for UI display)
		atomic.AddUint64(&test.testResult.bw, uint64(n))
		atomic.AddUint64(&test.testResult.totalBw, uint64(n))

		// Also update session stats if in multi-client mode
		if sessStats != nil {
			atomic.AddUint64(&sessStats.bw, uint64(n))
			atomic.AddUint64(&sessStats.totalBw, uint64(n))
		}

		// Periodically update lastAccess to keep test active (every ~100ms)
		if time.Since(lastAccessUpdate) > (100 * time.Millisecond) {
			test.lastAccess = time.Now()
			lastAccessUpdate = time.Now()
		}

		if clientParam.Reverse {
			sentBytes += uint64(n)
			start, waitTime, sentBytes, bytesToSend = enforceThrottle(start, waitTime, totalBytesToSend, sentBytes, bufferLen)
		}
	}
}

func srvrRunTCPLatencyTest(test *ethrTest, clientParam EthrClientParam, conn net.Conn) {
	// Activate the test when connection starts
	test.isDormant = false

	bytes := make([]byte, clientParam.BufferSize)
	rttCount := clientParam.RttCount
	latencyNumbers := make([]time.Duration, rttCount)

	// Update lastAccess to keep test active
	test.lastAccess = time.Now()

	for {
		_, err := io.ReadFull(conn, bytes)
		if err != nil {
			ui.printDbg("Error receiving data for latency test: %v", err)
			return
		}

		// Update lastAccess periodically
		test.lastAccess = time.Now()

		for i := uint32(0); i < rttCount; i++ {
			s1 := time.Now()
			_, err = conn.Write(bytes)
			if err != nil {
				ui.printDbg("Error sending data for latency test: %v", err)
				return
			}
			_, err = io.ReadFull(conn, bytes)
			if err != nil {
				ui.printDbg("Error receiving data for latency test: %v", err)
				return
			}
			e2 := time.Since(s1)
			latencyNumbers[i] = e2
		}
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
		atomic.SwapUint64(&test.testResult.latency, uint64(elapsed.Nanoseconds()))
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
}

func srvrRunUDPServer() error {
	// Use ListenConfig to set SO_REUSEADDR for faster port reuse after close
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR to allow binding to a port in TIME_WAIT state
				opErr = setSockOptReuseAddr(fd)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	conn, err := lc.ListenPacket(context.Background(), Udp(), gLocalIP+":"+gEthrPortStr)
	if err != nil {
		ui.printDbg("Error listening on %s for UDP pkt/s tests: %v", gEthrPortStr, err)
		return err
	}

	l := conn.(*net.UDPConn)

	// Store listener globally for cleanup on cancellation
	gUDPListener = l

	ui.printDbg("UDP server listening on: %s", l.LocalAddr().String())
	ui.printDbg("NOTE: If clients send large UDP packets (>MTU), fragmentation may cause packet loss.")
	ui.printDbg("Virtual networks (WSL, VMs, VPNs) often drop fragmented UDP. Advise clients to use: -l 1400")
	// Set socket buffer to 4MB per CPU so we can queue 4MB per CPU in case Ethr is not
	// able to keep up temporarily.
	err = l.SetReadBuffer(runtime.NumCPU() * 4 * 1024 * 1024)
	if err != nil {
		ui.printDbg("Failed to set ReadBuffer on UDP socket: %v", err)
	}
	//
	// We use NumCPU here instead of NumThreads passed from client. The
	// reason is that for UDP, there is no connection, so all packets come
	// on same CPU, so it isn't clear if there are any benefits to running
	// more threads than NumCPU(). TODO: Evaluate this in future.
	//
	for i := 0; i < runtime.NumCPU(); i++ {
		go srvrRunUDPPacketHandler(l)
	}
	return nil
}

func srvrRunUDPPacketHandler(conn *net.UDPConn) {
	// This local map aids in efficiency to look up a test based on client's IP
	// address. We could use createOrGetTest but that takes a global lock.
	tests := make(map[string]*ethrTest)
	// For UDP, allocate buffer that can accomodate largest UDP datagram.
	readBuffer := make([]byte, 64*1024)
	n, remoteIP, err := 0, new(net.UDPAddr), error(nil)

	// This function handles UDP tests that came from clients that are no longer
	// sending any traffic. This is poor man's garbage collection to ensure the
	// server doesn't end up printing dormant client related statistics as UDP
	// has no reliable way to detect if client is active or not.
	go func() {
		for {
			time.Sleep(100 * time.Millisecond)
			for k, v := range tests {
				// Skip tests with control channel - they use deterministic start/end signaling
				if v.ctrlConn != nil {
					continue
				}

				// At 200ms of no activity, mark the test in-active so stats stop
				// printing (only for non-control-channel tests).
				if time.Since(v.lastAccess) > (200 * time.Millisecond) {
					v.isDormant = true
					ethrUnused(k)
				}
				// At 2s of no activity, delete the test by assuming that client
				// has stopped (only for non-control-channel tests).
				if time.Since(v.lastAccess) > (2 * time.Second) {
					ui.printDbg("Deleting UDP test from server: %v, lastAccess: %v", k, v.lastAccess)
					safeDeleteTest(v)
					delete(tests, k)
				}
			}
		}
	}()
	for err == nil {
		n, remoteIP, err = conn.ReadFromUDP(readBuffer)
		if err != nil {
			ui.printDbg("Error receiving data from UDP for bandwidth test: %v", err)
			continue
		}
		ethrUnused(remoteIP)
		ethrUnused(n)
		server, portStr, _ := net.SplitHostPort(remoteIP.String())
		portNum, _ := strconv.Atoi(portStr)
		remoteAddrStr := remoteIP.String()

		// Try to look up session stats by IP:port first, then fall back to port-only
		sessionStatsPtr := getSessionStatsByUDPAddr(remoteAddrStr, portNum)
		if sessionStatsPtr != nil {
			// Found session-based stats - use those
			sessionStatsPtr.lastAccess = time.Now()
			atomic.AddUint64(&sessionStatsPtr.pps, 1)
			atomic.AddUint64(&sessionStatsPtr.bw, uint64(n))
			atomic.AddUint64(&sessionStatsPtr.totalPps, 1)
			atomic.AddUint64(&sessionStatsPtr.totalBw, uint64(n))

			// Also update the test object for UI display (using IP lookup)
			test, found := tests[server]
			if !found {
				var isNew bool
				test, isNew = createOrGetTest(server, UDP, All)
				if test != nil {
					tests[server] = test
				}
				if isNew {
					ui.printDbg("Creating UDP test from server: %v, lastAccess: %v", server, time.Now())
					ui.emitTestHdr(test)
				}
			}
			if test != nil {
				test.isDormant = false
				test.lastAccess = time.Now()
				atomic.AddUint64(&test.testResult.pps, 1)
				atomic.AddUint64(&test.testResult.bw, uint64(n))
				// Don't update totalPps/totalBw on test object - session stats has those
			}
			continue
		}

		// No session match found - accept traffic anyway and track by IP
		// This handles NAT scenarios and -ncc (no control channel) mode
		ethrUnused(portStr)
		test, found := tests[server]
		if !found {
			var isNew bool
			test, isNew = createOrGetTest(server, UDP, All)
			if test != nil {
				tests[server] = test
			}
			if isNew {
				ui.printDbg("Creating new UDP test for client IP: %s", server)
				ui.emitTestHdr(test)
			}
		}
		if test != nil {
			test.isDormant = false
			test.lastAccess = time.Now()
			atomic.AddUint64(&test.testResult.pps, 1)
			atomic.AddUint64(&test.testResult.bw, uint64(n))
			atomic.AddUint64(&test.testResult.totalPps, 1)
			atomic.AddUint64(&test.testResult.totalBw, uint64(n))
		} else {
			ui.printDbg("Unable to create test for UDP from client %s:%s", server, portStr)
		}
	}
}
