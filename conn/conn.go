package conn

import (
	"fmt"
	"log"
	"net"
)

// UDPConn interface for UDP connections - allows mocking for tests
type UDPConn interface {
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
	Close() error
}

// SetupUDP creates and binds a UDP socket on the specified port
func SetupUDP(listenPort int) (UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind UDP socket: %v", err)
	}

	log.Printf("UDP socket listening on port %d", listenPort)
	return conn, nil
}
