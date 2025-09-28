package test

import (
	"net"

	"github.com/drio/miniwg/conn"
	"github.com/drio/miniwg/tun"
)

// Compile-time interface compliance checks
var _ conn.UDPConn = (*MockUDPConn)(nil)
var _ tun.TUNDevice = (*MockTUN)(nil)

// MockUDPConn simulates a UDP connection using channels
type MockUDPConn struct {
	// Channel to receive packets that would come from the network
	inbound chan UDPPacket
	// Channel where packets written to this UDP connection go
	outbound chan UDPPacket
	// Local address simulation
	localAddr *net.UDPAddr
}

type UDPPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

// NewMockUDPConn creates a mock UDP connection
func NewMockUDPConn(localPort int) *MockUDPConn {
	return &MockUDPConn{
		inbound:  make(chan UDPPacket, 100),
		outbound: make(chan UDPPacket, 100),
		localAddr: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: localPort,
		},
	}
}

// ReadFromUDP simulates reading from UDP - blocks until packet arrives
func (m *MockUDPConn) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	packet := <-m.inbound
	n := copy(buf, packet.Data)
	return n, packet.Addr, nil
}

// WriteToUDP simulates writing to UDP - puts packet in outbound channel
func (m *MockUDPConn) WriteToUDP(data []byte, addr *net.UDPAddr) (int, error) {
	// Make a copy to avoid memory issues
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	packet := UDPPacket{
		Data: dataCopy,
		Addr: addr,
	}

	// Non-blocking send
	select {
	case m.outbound <- packet:
		return len(data), nil
	default:
		// Channel full - simulate dropped packet
		return len(data), nil
	}
}

// Close closes the mock connection
func (m *MockUDPConn) Close() error {
	close(m.inbound)
	close(m.outbound)
	return nil
}

// InjectPacket simulates a packet arriving from the network
func (m *MockUDPConn) InjectPacket(data []byte, fromAddr *net.UDPAddr) {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	packet := UDPPacket{
		Data: dataCopy,
		Addr: fromAddr,
	}

	select {
	case m.inbound <- packet:
		// Packet injected
	default:
		// Channel full - drop packet
	}
}

// ReadOutbound reads a packet that was written to this connection (non-blocking)
func (m *MockUDPConn) ReadOutbound() *UDPPacket {
	select {
	case packet := <-m.outbound:
		return &packet
	default:
		return nil
	}
}

// MockTUN simulates a TUN interface using channels
type MockTUN struct {
	// Channel to receive packets written to TUN (app → network)
	inbound chan []byte
	// Channel where packets read from TUN come from (network → app)
	outbound chan []byte
}

// NewMockTUN creates a mock TUN interface
func NewMockTUN() *MockTUN {
	return &MockTUN{
		inbound:  make(chan []byte, 100),
		outbound: make(chan []byte, 100),
	}
}

// Read simulates reading from TUN - blocks until packet available
func (m *MockTUN) Read(buf []byte) (int, error) {
	packet := <-m.outbound
	n := copy(buf, packet)
	return n, nil
}

// Write simulates writing to TUN - puts packet in inbound channel
func (m *MockTUN) Write(data []byte) (int, error) {
	// Make a copy to avoid memory issues
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	select {
	case m.inbound <- dataCopy:
		return len(data), nil
	default:
		// Channel full - simulate dropped packet
		return len(data), nil
	}
}

// Close closes the mock TUN
func (m *MockTUN) Close() error {
	close(m.inbound)
	close(m.outbound)
	return nil
}

// InjectPacket simulates a packet coming from the network to this TUN
func (m *MockTUN) InjectPacket(data []byte) {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	select {
	case m.outbound <- dataCopy:
		// Packet injected
	default:
		// Channel full - drop packet
	}
}

// ReadInbound reads a packet that was written to TUN (non-blocking)
func (m *MockTUN) ReadInbound() []byte {
	select {
	case packet := <-m.inbound:
		return packet
	default:
		return nil
	}
}
