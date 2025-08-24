// timers.go
//
// Basic timer management for session lifecycle
//
// Contains:
// - Rekey timer management (initiate new handshake every 120s)
// - Keepalive timer management (send empty packet every 10s when idle)
// - Handshake timeout handling (retry failed handshakes)
// - Timer cleanup and reset functions
// - Basic timer state tracking

package main

import "time"

// Timer constants from WireGuard specification
const (
	REKEY_AFTER_TIME  = 120 * time.Second
	REJECT_AFTER_TIME = 180 * time.Second
	REKEY_TIMEOUT     = 5 * time.Second
	KEEPALIVE_TIMEOUT = 10 * time.Second
)