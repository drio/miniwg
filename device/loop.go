// loop.go
//
// Event-driven architecture for coordinating WireGuard operations.
// Uses separate goroutines for TUN reading, UDP reading, and timer management,
// all communicating through buffered channels to a central event loop.
//
// Flow control: All channel sends use non-blocking select statements to prevent
// deadlocks. When buffers are full, packets/events are dropped with logging,
// ensuring the system remains responsive under load rather than blocking.

package device

import (
	"fmt"
	"log"
	"net"
)

const (
	HandshakeEventInitiation = "initiation"
	HandshakeEventResponse   = "response"
)

const (
	TimerEventRekey     = "rekey"
	TimerEventKeepalive = "keepalive"
	TimerEventRetry     = "retry"
)

const (
	StandardMTU        = 1500
	WireGuardMaxPacket = 2048
	QueuedPacketBuffer = 100
	EventBuffer        = 10
)

type HandshakeEvent struct {
	Type string
	Data []byte
	Addr *net.UDPAddr
}

type TimerEvent struct {
	Type string
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

		if wg.debug {
			log.Printf("TUN: received %d bytes", n)
		}
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

		if wg.debug {
			log.Printf("UDP: received %d bytes from %s, type=%d", n, addr, msgType)
		}

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

	for range wg.rekeyTimer.C {
		// Non-blocking send - drop timer event if main loop is overwhelmed
		select {
		case timerChan <- TimerEvent{Type: TimerEventRekey}:
		default:
			log.Printf("Timer event dropped - queue full")
		}
		wg.rekeyTimer.Reset(REKEY_AFTER_TIME)
		// TODO: Add keepalive and retry timers using additional goroutines
	}
}

// run starts the main event loop that coordinates all WireGuard operations
func (wg *MiniWG) Run() {
	log.Println("Starting MiniWG main event loop")

	queuedPackets := make(chan QueuedPacket, QueuedPacketBuffer)
	handshakeEvents := make(chan HandshakeEvent, EventBuffer)
	timerEvents := make(chan TimerEvent, EventBuffer)

	go wg.tunReader(queuedPackets)
	go wg.udpReader(handshakeEvents)
	go wg.timerManager(timerEvents)

	for {
		select {
		case packet := <-queuedPackets:
			wg.handleTUNPacket(packet.Data)

		case hsEvent := <-handshakeEvents:
			wg.handleHandshakeEvent(hsEvent)

		case timer := <-timerEvents:
			wg.handleTimerEvent(timer)

		case <-wg.done:
			log.Println("MiniWG main event loop shutting down")
			return
		}
	}
}

// handleTUNPacket processes packets from the TUN interface
func (wg *MiniWG) handleTUNPacket(packet []byte) {
	if !wg.hasSession {
		if wg.debug {
			log.Printf("No session - queuing packet and initiating handshake")
		}

		// Queue the packet for later transmission
		wg.queuePacket(packet)

		// Initiate handshake if not already in progress
		if err := wg.initiateHandshake(); err != nil {
			log.Printf("Failed to initiate handshake: %v", err)
		}
		return
	}

	if wg.debug {
		log.Printf("Encrypting and forwarding packet")
	}
	if err := wg.handleTunnelTraffic(packet); err != nil {
		log.Printf("Failed to send encrypted packet: %v", err)
	}
}

// handleHandshakeEvent processes handshake messages
func (wg *MiniWG) handleHandshakeEvent(event HandshakeEvent) {
	switch event.Type {
	case HandshakeEventInitiation:
		// We are the RESPONDER - peer initiated handshake with us
		log.Printf("Processing handshake initiation from %s", event.Addr)

		// Step 1: Process the initiation message
		var lastTimestamp [12]byte // TODO: Use actual last timestamp for replay protection
		responderState, err := ConsumeMessageInitiation(
			event.Data,
			wg.privateKey,
			wg.publicKey,
			lastTimestamp,
		)
		if err != nil {
			log.Printf("Failed to process handshake initiation: %v", err)
			return
		}

		// Step 2: Store the responder state
		wg.responderState = responderState

		// Step 3: Create handshake response
		responseMsg, finalState, err := CreateMessageResponse(responderState, wg.localIndex)
		if err != nil {
			log.Printf("Failed to create handshake response: %v", err)
			return
		}

		// Step 4: Send response back to peer
		responseBytes := responseMsg.Marshal()
		_, err = wg.udp.WriteToUDP(responseBytes, event.Addr)
		if err != nil {
			log.Printf("Failed to send handshake response: %v", err)
			return
		}

		log.Printf("Sent handshake response (%d bytes) to %s", len(responseBytes), event.Addr)

		// Step 5: Extract transport keys and establish session
		sendKey, recvKey, err := deriveTransportKeys(finalState.chainingKey)
		if err != nil {
			log.Printf("Failed to derive transport keys: %v", err)
			return
		}

		// Establish the session with the derived keys
		// For responder: we send with our derived key, receive with initiator's derived key
		wg.establishSession(recvKey, sendKey, responderState.initiatorSenderIndex)

		log.Printf("Session established with %s - keys derived and stored", event.Addr)

		// Send any packets that were queued during handshake
		wg.sendQueuedPackets()

	case HandshakeEventResponse:
		// We are the INITIATOR - peer responded to our handshake
		log.Printf("Processing handshake response from %s", event.Addr)

		// Check if we have saved initiator state
		if wg.initiatorState == nil {
			log.Printf("Received handshake response but no initiator state saved - ignoring")
			return
		}

		// Step 1: Parse response message to get responder's sender index
		var response HandshakeResponse
		if err := response.Unmarshal(event.Data); err != nil {
			log.Printf("Failed to unmarshal handshake response: %v", err)
			return
		}

		// Step 2: Process the response message
		finalState, err := ConsumeMessageResponse(event.Data, wg.initiatorState)
		if err != nil {
			log.Printf("Failed to process handshake response: %v", err)
			return
		}

		log.Printf("Handshake completed successfully with %s", event.Addr)

		// Step 3: Extract transport keys and establish session
		sendKey, recvKey, err := deriveTransportKeys(finalState.chainingKey)
		if err != nil {
			log.Printf("Failed to derive transport keys: %v", err)
			return
		}

		// For initiator: we send with our derived key, receive with responder's derived key
		wg.establishSession(sendKey, recvKey, response.Sender)

		log.Printf("Session established with %s - keys derived and stored", event.Addr)

		wg.sendQueuedPackets()

		wg.initiatorState = nil
		wg.isHandshaking = false
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

// initiateHandshake starts a new handshake with the configured peer
// Uses double-checked locking pattern like WireGuard-Go to prevent races
func (wg *MiniWG) initiateHandshake() error {
	wg.mutex.RLock()
	if wg.isHandshaking {
		wg.mutex.RUnlock()
		log.Printf("Handshake already in progress - skipping initiation")
		return nil
	}
	wg.mutex.RUnlock()

	// Check if we have peer configuration
	if wg.peerAddr == nil {
		return fmt.Errorf("no peer endpoint configured")
	}

	// Double-checked locking: acquire write lock and check again
	wg.mutex.Lock()
	defer wg.mutex.Unlock()

	if wg.isHandshaking {
		log.Printf("Handshake already in progress - skipping initiation")
		return nil
	}

	log.Printf("Initiating handshake with peer %s", wg.peerAddr)

	// Mark handshake as in progress
	wg.isHandshaking = true

	wg.mutex.Unlock()
	initiationMsg, initiatorState, err := CreateMessageInitiation(
		wg.privateKey,
		wg.publicKey,
		wg.peerKey,
		wg.localIndex,
	)
	wg.mutex.Lock()

	if err != nil {
		wg.isHandshaking = false
		return fmt.Errorf("failed to create handshake initiation: %v", err)
	}

	// Store initiator state for processing the response
	wg.initiatorState = initiatorState

	// Send initiation message to peer (unlock for network I/O)
	initiationBytes := initiationMsg.Marshal()
	wg.mutex.Unlock()
	_, err = wg.udp.WriteToUDP(initiationBytes, wg.peerAddr)
	wg.mutex.Lock()

	if err != nil {
		// Clean up state on send failure
		wg.isHandshaking = false
		wg.initiatorState = nil
		return fmt.Errorf("failed to send handshake initiation: %v", err)
	}

	log.Printf("Sent handshake initiation (%d bytes) to %s", len(initiationBytes), wg.peerAddr)
	return nil
}
