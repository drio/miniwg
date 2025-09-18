// loop.go
//
// Event-driven architecture for coordinating WireGuard operations.
// Uses separate goroutines for TUN reading, UDP reading, and timer management,
// all communicating through buffered channels to a central event loop.
//
// Flow control: All channel sends use non-blocking select statements to prevent
// deadlocks. When buffers are full, packets/events are dropped with logging,
// ensuring the system remains responsive under load rather than blocking.

package main

import (
	"log"
	"net"
)

// Handshake event type constants
const (
	HandshakeEventInitiation = "initiation"
	HandshakeEventResponse   = "response"
)

// Timer event type constants
const (
	TimerEventRekey     = "rekey"
	TimerEventKeepalive = "keepalive"
	TimerEventRetry     = "retry"
)

// Network and buffer size constants
const (
	StandardMTU        = 1500 // Standard Ethernet MTU
	WireGuardMaxPacket = 2048 // WireGuard maximum packet size
	QueuedPacketBuffer = 100  // Buffer size for queued packets channel
	EventBuffer        = 10   // Buffer size for event channels
)

// Event types for the main coordination loop
type HandshakeEvent struct {
	Type string      // HandshakeEventInitiation, HandshakeEventResponse
	Data []byte
	Addr *net.UDPAddr
}

type TimerEvent struct {
	Type string // TimerEventRekey, TimerEventKeepalive, TimerEventRetry
}

// Channel for queuing outbound packets during handshake
type QueuedPacket struct {
	Data []byte
}

// getMessageType extracts the message type from a WireGuard packet
func (wg *MiniWG) getMessageType(packet []byte) uint8 {
	if len(packet) < 1 {
		return 0
	}
	return packet[0]
}

// tunReader reads packets from the TUN interface and sends them to the main loop
func (wg *MiniWG) tunReader(outbound chan<- QueuedPacket) {
	log.Println("TUN reader started")

	for {
		packet := make([]byte, StandardMTU)
		n, err := wg.tun.Read(packet)
		if err != nil {
			log.Printf("TUN read error: %v", err)
			continue
		}

		log.Printf("TUN: received %d bytes", n)
		// Non-blocking send - drop packet if main loop is overwhelmed
		select {
		case outbound <- QueuedPacket{Data: packet[:n]}:
			// Packet queued successfully
		default:
			log.Printf("TUN packet dropped - queue full")
		}
	}
}

// udpReader reads packets from the UDP socket and routes them based on message type
func (wg *MiniWG) udpReader(handshakeChan chan<- HandshakeEvent) {
	log.Println("UDP reader started")

	for {
		packet := make([]byte, WireGuardMaxPacket)
		n, addr, err := wg.udp.ReadFromUDP(packet)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		data := packet[:n]
		msgType := wg.getMessageType(data)

		log.Printf("UDP: received %d bytes from %s, type=%d", n, addr, msgType)

		switch msgType {
		case MessageTypeHandshakeInitiation:
			// Non-blocking send - drop handshake if main loop is overwhelmed
			select {
			case handshakeChan <- HandshakeEvent{
				Type: HandshakeEventInitiation,
				Data: data,
				Addr: addr,
			}:
				// Handshake queued successfully
			default:
				log.Printf("Handshake initiation dropped - queue full")
			}
		case MessageTypeHandshakeResponse:
			// Non-blocking send - drop handshake if main loop is overwhelmed
			select {
			case handshakeChan <- HandshakeEvent{
				Type: HandshakeEventResponse,
				Data: data,
				Addr: addr,
			}:
				// Handshake queued successfully
			default:
				log.Printf("Handshake response dropped - queue full")
			}
		case MessageTypeTransportData:
			// Handle transport data directly (decrypt & write to TUN)
			// Drop packets that fail to decrypt - following WireGuard's approach
			if err := wg.handleTransportData(data); err != nil {
				log.Printf("Failed to process transport data: %v", err)
			}
		default:
			log.Printf("Unknown message type: %d", msgType)
		}
	}
}

// timerManager handles periodic timer events (basic implementation)
func (wg *MiniWG) timerManager(timerChan chan<- TimerEvent) {
	log.Println("Timer manager started")

	// Use range to listen for timer events
	for range wg.rekeyTimer.C {
		// Non-blocking send - drop timer event if main loop is overwhelmed
		select {
		case timerChan <- TimerEvent{Type: TimerEventRekey}:
			// Timer event queued successfully
		default:
			log.Printf("Timer event dropped - queue full")
		}
		// Reset timer for next rekey interval
		wg.rekeyTimer.Reset(REKEY_AFTER_TIME)
		// TODO: Add keepalive and retry timers using additional goroutines
	}
}

// run starts the main event loop that coordinates all WireGuard operations
func (wg *MiniWG) run() {
	log.Println("Starting MiniWG main event loop")

	// Create communication channels
	queuedPackets := make(chan QueuedPacket, QueuedPacketBuffer)
	handshakeEvents := make(chan HandshakeEvent, EventBuffer)
	timerEvents := make(chan TimerEvent, EventBuffer)

	// Start goroutines
	go wg.tunReader(queuedPackets)
	go wg.udpReader(handshakeEvents)
	go wg.timerManager(timerEvents)

	// Main coordination loop
	for {
		select {
		case packet := <-queuedPackets:
			wg.handleTUNPacket(packet.Data)

		case hsEvent := <-handshakeEvents:
			wg.handleHandshakeEvent(hsEvent)

		case timer := <-timerEvents:
			wg.handleTimerEvent(timer)
		}
	}
}

// handleTUNPacket processes packets from the TUN interface
func (wg *MiniWG) handleTUNPacket(packet []byte) {
	if !wg.hasSession {
		log.Printf("No session - queuing packet and initiating handshake")
		// TODO: Queue packet for later transmission
		// TODO: Initiate handshake if not already in progress
		return
	}

	log.Printf("Session active - encrypting and forwarding packet")
	// TODO: Encrypt packet using transport.go functions
	// TODO: Send encrypted packet via UDP
}

// handleHandshakeEvent processes handshake messages
func (wg *MiniWG) handleHandshakeEvent(event HandshakeEvent) {
	log.Printf("Handling handshake event: %s from %s", event.Type, event.Addr)

	switch event.Type {
	case HandshakeEventInitiation:
		log.Println("TODO: Process handshake initiation")
		// TODO: Use processHandshakeInitiation from handshake.go

	case HandshakeEventResponse:
		log.Println("TODO: Process handshake response")
		// TODO: Use processHandshakeResponse from handshake.go
	}
}

// handleTimerEvent processes timer-based events
func (wg *MiniWG) handleTimerEvent(event TimerEvent) {
	log.Printf("Handling timer event: %s", event.Type)

	switch event.Type {
	case TimerEventRekey:
		log.Println("TODO: Initiate rekey handshake")

	case TimerEventKeepalive:
		log.Println("TODO: Send keepalive packet")

	case TimerEventRetry:
		log.Println("TODO: Retry handshake")
	}
}

