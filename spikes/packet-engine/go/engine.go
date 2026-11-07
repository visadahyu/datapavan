// Package gvisorengine is engine 3 of the packet-engine spike (ADR 0012): gVisor's netstack
// terminates every connection from the tunnel, and each one is relayed over an ordinary socket of
// the watch app's own, outside the tunnel. gomobile binds it for Kotlin as gvisorengine.Gvisorengine,
// with the same surface as the Rust engines: start, stop, and the counters in the same order.
//
// Unlike the two Rust engines, the TCP handshake with the app completes only once the real server
// has accepted the connection, so an app sees a refused or unreachable server as such.
package gvisorengine

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Platform is what the engine asks of Android, implemented in Kotlin: the app that owns a flow,
// ConnectivityManager.getConnectionOwnerUid, or -1.
type Platform interface {
	OwnerUid(protocol int32, src []byte, srcPort int32, dst []byte, dstPort int32) int32
}

const (
	tcpFlows = iota
	udpFlows
	bytesUp
	bytesDown
	ownerLookups
	ownerNanos
	ownerUnknown
	connectErrors
	packetsIn
	packetsOut
	counterCount
)

const udpIdle = 60 * time.Second

var (
	mu       sync.Mutex
	running  *stack.Stack
	tunFD    = -1
	counters [counterCount]atomic.Int64
)

func add(i int, n int64) { counters[i].Add(n) }

// Start runs the engine on the tunnel's descriptor, which it owns from then on.
func Start(fd int64, mtu int64, platform Platform) bool {
	Stop()
	for i := range counters {
		counters[i].Store(0)
	}
	if err := unix.SetNonblock(int(fd), true); err != nil {
		return false
	}
	link, err := fdbased.New(&fdbased.Options{FDs: []int{int(fd)}, MTU: uint32(mtu)})
	if err != nil {
		return false
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if e := s.CreateNIC(1, link); e != nil {
		s.Close()
		return false
	}
	// Every destination is "local": the stack answers for any address the apps reach.
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})

	forwardTCP := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		add(tcpFlows, 1)
		lookUp(platform, 6, id)
		upstream, err := net.DialTimeout("tcp", hostPort(id.LocalAddress, id.LocalPort), 10*time.Second)
		if err != nil {
			add(connectErrors, 1)
			r.Complete(true)
			return
		}
		var queue waiter.Queue
		endpoint, e := r.CreateEndpoint(&queue)
		if e != nil {
			upstream.Close()
			r.Complete(true)
			return
		}
		r.Complete(false)
		relay(gonet.NewTCPConn(&queue, endpoint), upstream)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwardTCP.HandlePacket)

	forwardUDP := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var queue waiter.Queue
		endpoint, e := r.CreateEndpoint(&queue)
		if e != nil {
			return false
		}
		add(udpFlows, 1)
		go func() {
			lookUp(platform, 17, id)
			app := gonet.NewUDPConn(&queue, endpoint)
			upstream, err := net.Dial("udp", hostPort(id.LocalAddress, id.LocalPort))
			if err != nil {
				add(connectErrors, 1)
				app.Close()
				return
			}
			relayUDP(app, upstream)
		}()
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, forwardUDP.HandlePacket)

	mu.Lock()
	running, tunFD = s, int(fd)
	mu.Unlock()
	return true
}

// Stop stops the engine and closes the tunnel's descriptor.
func Stop() {
	mu.Lock()
	s, fd := running, tunFD
	running, tunFD = nil, -1
	mu.Unlock()
	if s == nil {
		return
	}
	s.Close()
	s.Wait()
	if fd >= 0 {
		unix.Close(fd)
	}
}

// Stats gives the counters as comma-separated numbers, in the order of the Rust engines' Stats.
func Stats() string {
	mu.Lock()
	s := running
	mu.Unlock()
	if s != nil {
		if nic, ok := s.NICInfo()[1]; ok {
			counters[packetsIn].Store(int64(nic.Stats.Rx.Packets.Value()))
			counters[packetsOut].Store(int64(nic.Stats.Tx.Packets.Value()))
		}
	}
	values := make([]string, counterCount)
	for i := range counters {
		values[i] = strconv.FormatInt(counters[i].Load(), 10)
	}
	return strings.Join(values, ",")
}

func hostPort(address tcpip.Address, port uint16) string {
	return net.JoinHostPort(net.IP(address.AsSlice()).String(), strconv.Itoa(int(port)))
}

// lookUp asks Android which app opened the flow and counts the time it took. In gVisor's terms the
// app is the remote end and the destination the local one.
func lookUp(platform Platform, protocol int32, id stack.TransportEndpointID) {
	started := time.Now()
	uid := platform.OwnerUid(protocol, id.RemoteAddress.AsSlice(), int32(id.RemotePort), id.LocalAddress.AsSlice(), int32(id.LocalPort))
	add(ownerLookups, 1)
	add(ownerNanos, time.Since(started).Nanoseconds())
	if uid < 0 {
		add(ownerUnknown, 1)
	}
}

// relay copies both ways and counts each direction as it goes.
func relay(app net.Conn, upstream net.Conn) {
	defer app.Close()
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstream, app)
		add(bytesUp, n)
		if c, ok := upstream.(*net.TCPConn); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(app, upstream)
		add(bytesDown, n)
		if c, ok := app.(*gonet.TCPConn); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func relayUDP(app *gonet.UDPConn, upstream net.Conn) {
	defer app.Close()
	defer upstream.Close()
	go func() {
		buffer := make([]byte, 65535)
		for {
			upstream.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := upstream.Read(buffer)
			if err != nil {
				app.Close()
				return
			}
			if _, err := app.Write(buffer[:n]); err != nil {
				return
			}
			add(bytesDown, int64(n))
		}
	}()
	buffer := make([]byte, 65535)
	for {
		app.SetReadDeadline(time.Now().Add(udpIdle))
		n, err := app.Read(buffer)
		if err != nil {
			return
		}
		if _, err := upstream.Write(buffer[:n]); err != nil {
			return
		}
		add(bytesUp, int64(n))
	}
}

// Version names the gVisor build, for the findings.
func Version() string { return fmt.Sprintf("gvisor %s", "v0.0.0-20261107083731-df6600af9f2c") }
