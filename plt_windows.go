// +build windows

//-----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
//-----------------------------------------------------------------------------
package main

import (
	"context"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	tm "github.com/nsf/termbox-go"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	proc_get_tcp_statistics_ex = iphlpapi.NewProc("GetTcpStatisticsEx")
	proc_get_if_entry2         = iphlpapi.NewProc("GetIfEntry2")
	proc_get_console_window    = kernel32.NewProc("GetConsoleWindow")
	proc_get_system_menu       = user32.NewProc("GetSystemMenu")
	proc_delete_menu           = user32.NewProc("DeleteMenu")

	// Windows ICMP API for traceroute (doesn't require admin or firewall exceptions)
	proc_icmp_create_file = iphlpapi.NewProc("IcmpCreateFile")
	proc_icmp_close_handle = iphlpapi.NewProc("IcmpCloseHandle")
	proc_icmp_send_echo    = iphlpapi.NewProc("IcmpSendEcho")
)

type ethrNetDevInfo struct {
	bytes   uint64
	packets uint64
	drop    uint64
	errs    uint64
}

func getNetDevStats(stats *ethrNetStat) {
	ifs, err := net.Interfaces()
	if err != nil {
		ui.printErr("%v", err)
		return
	}

	for _, ifi := range ifs {
		if (ifi.Flags&net.FlagUp) == 0 || strings.Contains(ifi.Name, "Pseudo") {
			continue
		}
		row, err := getIfEntry2(uint32(ifi.Index))
		if err != nil {
			ui.printErr("%v", err)
			return
		}
		rxInfo := ethrNetDevInfo{
			bytes:   uint64(row.InOctets),
			packets: uint64(row.InUcastPkts),
			drop:    uint64(row.InDiscards),
			errs:    uint64(row.InErrors),
		}
		txInfo := ethrNetDevInfo{
			bytes:   uint64(row.OutOctets),
			packets: uint64(row.OutUcastPkts),
			drop:    uint64(row.OutDiscards),
			errs:    uint64(row.OutErrors),
		}
		netStats := ethrNetDevStat{
			interfaceName: ifi.Name,
			rxBytes:       rxInfo.bytes,
			txBytes:       txInfo.bytes,
			rxPkts:        rxInfo.packets,
			txPkts:        txInfo.packets,
		}
		stats.netDevStats = append(stats.netDevStats, netStats)
	}
}

type mib_tcpstats struct {
	DwRtoAlgorithm uint32
	DwRtoMin       uint32
	DwRtoMax       uint32
	DwMaxConn      uint32
	DwActiveOpens  uint32
	DwPassiveOpens uint32
	DwAttemptFails uint32
	DwEstabResets  uint32
	DwCurrEstab    uint32
	DwInSegs       uint32
	DwOutSegs      uint32
	DwRetransSegs  uint32
	DwInErrs       uint32
	DwOutRsts      uint32
	DwNumConns     uint32
}

const (
	AF_INET  = 2
	AF_INET6 = 23
)

func getTCPStats(stats *ethrNetStat) (errcode error) {
	tcpStats := &mib_tcpstats{}
	r0, _, _ := syscall.Syscall(proc_get_tcp_statistics_ex.Addr(), 2,
		uintptr(unsafe.Pointer(tcpStats)), uintptr(AF_INET), 0)

	if r0 != 0 {
		errcode = syscall.Errno(r0)
		return
	}
	stats.tcpStats.segRetrans = uint64(tcpStats.DwRetransSegs)
	return
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

const (
	MAX_STRING_SIZE         = 256
	MAX_PHYS_ADDRESS_LENGTH = 32
	pad0for64_4for32        = 0
)

type mibIfRow2 struct {
	InterfaceLuid               uint64
	InterfaceIndex              uint32
	InterfaceGuid               guid
	Alias                       [MAX_STRING_SIZE + 1]uint16
	Description                 [MAX_STRING_SIZE + 1]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [MAX_PHYS_ADDRESS_LENGTH]uint8
	PermanentPhysicalAddress    [MAX_PHYS_ADDRESS_LENGTH]uint8
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags uint32
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGuid                 guid
	ConnectionType              uint32
	padding1                    [pad0for64_4for32]byte
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

func getIfEntry2(ifIndex uint32) (mibIfRow2, error) {
	var res *mibIfRow2

	res = &mibIfRow2{InterfaceIndex: ifIndex}
	r0, _, _ := syscall.Syscall(proc_get_if_entry2.Addr(), 1,
		uintptr(unsafe.Pointer(res)), 0, 0)
	if r0 != 0 {
		return mibIfRow2{}, syscall.Errno(r0)
	}
	return *res, nil
}

func hideCursor() {
	tm.HideCursor()
}

const (
	MF_BYCOMMAND = 0x00000000
	SC_CLOSE     = 0xF060
	SC_MINIMIZE  = 0xF020
	SC_MAXIMIZE  = 0xF030
	SC_SIZE      = 0xF000
)

func blockWindowResize() {
	h, _, err := syscall.Syscall(proc_get_console_window.Addr(), 0, 0, 0, 0)
	if err != 0 {
		return
	}

	sysMenu, _, err := syscall.Syscall(proc_get_system_menu.Addr(), 2, h, 0, 0)
	if err != 0 {
		return
	}

	syscall.Syscall(proc_delete_menu.Addr(), 3, sysMenu, SC_MAXIMIZE, MF_BYCOMMAND)
	syscall.Syscall(proc_delete_menu.Addr(), 3, sysMenu, SC_SIZE, MF_BYCOMMAND)
}

func setSockOptInt(fd uintptr, level, opt, val int) (err error) {
	err = syscall.SetsockoptInt(syscall.Handle(fd), level, opt, val)
	if err != nil {
		ui.printErr("Failed to set socket option (%v) to value (%v) during Dial. Error: %s", opt, val, err)
	}
	return
}

// Windows ICMP API structures for traceroute
// IP_OPTION_INFORMATION for IcmpSendEcho
type ipOptionInfo struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// ICMP_ECHO_REPLY structure returned by IcmpSendEcho
type icmpEchoReply struct {
	Address       uint32 // Replying address (in network byte order)
	Status        uint32 // Reply IP_STATUS
	RoundTripTime uint32 // RTT in milliseconds
	DataSize      uint16 // Reply data size
	Reserved      uint16 // Reserved for system use
	Data          uintptr // Pointer to the reply data
	Options       ipOptionInfo // Reply options
}

// IP_STATUS codes
const (
	IP_SUCCESS               = 0
	IP_BUF_TOO_SMALL         = 11001
	IP_DEST_NET_UNREACHABLE  = 11002
	IP_DEST_HOST_UNREACHABLE = 11003
	IP_DEST_PROT_UNREACHABLE = 11004
	IP_DEST_PORT_UNREACHABLE = 11005
	IP_NO_RESOURCES          = 11006
	IP_BAD_OPTION            = 11007
	IP_HW_ERROR              = 11008
	IP_PACKET_TOO_BIG        = 11009
	IP_REQ_TIMED_OUT         = 11010
	IP_BAD_REQ               = 11011
	IP_BAD_ROUTE             = 11012
	IP_TTL_EXPIRED_TRANSIT   = 11013
	IP_TTL_EXPIRED_REASSEM   = 11014
	IP_PARAM_PROBLEM         = 11015
	IP_SOURCE_QUENCH         = 11016
	IP_OPTION_TOO_BIG        = 11017
	IP_BAD_DESTINATION       = 11018
	IP_GENERAL_FAILURE       = 11050
)

// WinIcmpSendEcho sends an ICMP echo request using Windows API
// This works without admin privileges and without firewall exceptions
// Returns: replying address (as string), round trip time, status code, error
func WinIcmpSendEcho(destIP string, ttl int, timeout uint32) (string, uint32, uint32, error) {
	// Parse destination IP
	ip := net.ParseIP(destIP)
	if ip == nil {
		return "", 0, 0, os.ErrInvalid
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", 0, 0, os.ErrInvalid // IPv6 not supported by IcmpSendEcho
	}
	destAddr := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24

	// Create ICMP handle
	handle, _, err := syscall.Syscall(proc_icmp_create_file.Addr(), 0, 0, 0, 0)
	if handle == 0 || handle == ^uintptr(0) {
		return "", 0, 0, err
	}
	defer syscall.Syscall(proc_icmp_close_handle.Addr(), 1, handle, 0, 0)

	// Prepare send data
	sendData := []byte("Ethr ICMP Probe")
	sendSize := uint16(len(sendData))

	// Prepare IP options with TTL
	opts := ipOptionInfo{
		Ttl: uint8(ttl),
		Tos: uint8(gTOS),
	}

	// Reply buffer needs to be large enough for ICMP_ECHO_REPLY + data + 8 bytes for ICMP error message
	replySize := uint32(unsafe.Sizeof(icmpEchoReply{})) + uint32(sendSize) + 8
	replyBuf := make([]byte, replySize)

	// Call IcmpSendEcho
	ret, _, _ := syscall.Syscall9(
		proc_icmp_send_echo.Addr(),
		8,
		handle,
		uintptr(destAddr),
		uintptr(unsafe.Pointer(&sendData[0])),
		uintptr(sendSize),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replySize),
		uintptr(timeout),
		0,
	)

	if ret == 0 {
		// No reply received (timeout)
		return "", 0, IP_REQ_TIMED_OUT, nil
	}

	// Parse reply
	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	
	// Convert address from network byte order to string
	addrBytes := make([]byte, 4)
	addrBytes[0] = byte(reply.Address)
	addrBytes[1] = byte(reply.Address >> 8)
	addrBytes[2] = byte(reply.Address >> 16)
	addrBytes[3] = byte(reply.Address >> 24)
	replyAddr := net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3]).String()

	return replyAddr, reply.RoundTripTime, reply.Status, nil
}

const (
	SIO_RCVALL             = syscall.IOC_IN | syscall.IOC_VENDOR | 1
	RCVALL_OFF             = 0
	RCVALL_ON              = 1
	RCVALL_SOCKETLEVELONLY = 2
	RCVALL_IPLEVEL         = 3
)

func IcmpNewConn(address string) (net.PacketConn, error) {
	// This is an attempt to work around the problem described here:
	// https://github.com/golang/go/issues/38427

	// First, get the correct local interface address, as SIO_RCVALL can't be set on a 0.0.0.0 listeners.
	dialedConn, err := net.Dial(Icmp(), address)
	if err != nil {
		return nil, err
	}
	localAddr := dialedConn.LocalAddr()
	dialedConn.Close()

	// Configure the setup routine in order to extract the socket handle.
	var socketHandle syscall.Handle
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(s uintptr) {
				socketHandle = syscall.Handle(s)
			})
		},
	}

	// Bind to interface.
	conn, err := cfg.ListenPacket(context.Background(), Icmp(), localAddr.String())
	if err != nil {
		return nil, err
	}

	// Set socket option to receive all packets, such as ICMP error messages.
	// This is somewhat dirty, as there is guarantee that socketHandle is still valid.
	// WARNING: The Windows Firewall might just drop the incoming packets you might want to receive.
	unused := uint32(0) // Documentation states that this is unused, but WSAIoctl fails without it.
	flag := uint32(RCVALL_IPLEVEL)
	size := uint32(unsafe.Sizeof(flag))
	err = syscall.WSAIoctl(socketHandle, SIO_RCVALL, (*byte)(unsafe.Pointer(&flag)), size, nil, 0, &unused, nil, 0)
	if err != nil {
		ui.printDbg("SIO_RCVALL failed (may need admin or firewall exception): %v", err)
		// Try without RCVALL - basic ICMP socket may still work for some cases
	} else {
		ui.printDbg("SIO_RCVALL succeeded - raw ICMP capture enabled")
	}

	return conn, nil
}

func VerifyPermissionForTest(testID EthrTestID) {
	if (testID.Type == TraceRoute || testID.Type == MyTraceRoute) &&
		(testID.Protocol == TCP) {
		if !IsAdmin() {
			ui.printErr("Error: %s %s test requires Administrator privileges on Windows.",
				protoToString(testID.Protocol), testToString(testID.Type))
			ui.printErr("Please run from an elevated command prompt (Run as Administrator).")
			ui.printErr("This is required to receive ICMP 'TTL exceeded' responses.")
			os.Exit(1)
		}
		ui.printMsg("Note: TCP traceroute on Windows requires Windows Firewall to allow")
		ui.printMsg("ICMP 'TTL exceeded' messages. If results show '???', run this")
		ui.printMsg("command as Administrator to add a firewall rule:")
		ui.printMsg("  netsh advfirewall firewall add rule name=\"ICMP TTL Exceeded\" protocol=icmpv4:11,any dir=in action=allow")
		ui.printMsg("Or use ICMP traceroute instead: -p icmp\n")
	}
}

func IsAdmin() bool {
	c, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		ui.printDbg("Process is not running as admin. Error: %v", err)
		return false
	}
	c.Close()
	return true
}

func SetTClass(fd uintptr, tos int) {
	return
}

// WinIcmpProbe performs a single ICMP probe using Windows API
// This is used for traceroute and works without admin privileges
func WinIcmpProbe(destIP string, ttl int, timeout uint32) (peerAddr string, rtt uint32, isLast bool, err error) {
	peerAddr, rtt, status, err := WinIcmpSendEcho(destIP, ttl, timeout)
	if err != nil {
		return "", 0, false, err
	}

	switch status {
	case IP_SUCCESS:
		// Reached destination
		isLast = true
		return peerAddr, rtt, isLast, nil
	case IP_TTL_EXPIRED_TRANSIT, IP_TTL_EXPIRED_REASSEM:
		// Intermediate hop responded
		return peerAddr, rtt, false, nil
	case IP_REQ_TIMED_OUT:
		// No response
		return "", 0, false, nil
	default:
		// Other error, but we got a reply address
		if peerAddr != "" && peerAddr != "0.0.0.0" {
			return peerAddr, rtt, false, nil
		}
		return "", 0, false, nil
	}
}

// setSockOptReuseAddr sets SO_REUSEADDR on a file descriptor
// On Windows, fd must be a syscall.Handle
func setSockOptReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
