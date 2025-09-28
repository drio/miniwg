package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/songgao/water"
	"golang.org/x/crypto/curve25519"
)

func (wg *MiniWG) loadConfig(configFile string) error {
	// Validate and clean the config file path to prevent directory traversal
	cleanPath := filepath.Clean(configFile)

	// Ensure the path doesn't contain directory traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid config file path: directory traversal not allowed")
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "PrivateKey":
			privateKeyBytes, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return fmt.Errorf("failed to decode private key: %v", err)
			}
			if len(privateKeyBytes) != 32 {
				return fmt.Errorf("private key must be 32 bytes")
			}
			copy(wg.privateKey[:], privateKeyBytes)

		case "PeerKey":
			peerKeyBytes, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return fmt.Errorf("failed to decode peer key: %v", err)
			}
			if len(peerKeyBytes) != 32 {
				return fmt.Errorf("peer key must be 32 bytes")
			}
			copy(wg.peerKey[:], peerKeyBytes)

		case "ListenPort":
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("failed to parse listen port: %v", err)
			}
			wg.listenPort = port

		case "PeerEndpoint":
			peerAddr, err := net.ResolveUDPAddr("udp", value)
			if err != nil {
				return fmt.Errorf("failed to resolve peer address: %v", err)
			}
			wg.peerAddr = peerAddr

		case "TunName":
			wg.tunName = value

		case "TunAddress":
			wg.tunAddress = value
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	// Validate required configuration values
	var missing []string

	if wg.privateKey == [32]byte{} {
		missing = append(missing, "PrivateKey")
	}
	if wg.peerKey == [32]byte{} {
		missing = append(missing, "PeerKey")
	}
	if wg.listenPort == 0 {
		missing = append(missing, "ListenPort")
	}
	if wg.peerAddr == nil {
		missing = append(missing, "PeerEndpoint")
	}
	if wg.tunName == "" {
		missing = append(missing, "TunName")
	}
	if wg.tunAddress == "" {
		missing = append(missing, "TunAddress")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration values: %v", missing)
	}

	curve25519.ScalarBaseMult(&wg.publicKey, &wg.privateKey)
	wg.localIndex = 0x12345678

	log.Printf("Local public key: %x", wg.publicKey)
	log.Printf("Peer public key: %x", wg.peerKey)
	log.Printf("Listen port: %d", wg.listenPort)
	log.Printf("Peer address: %s", wg.peerAddr)
	log.Printf("TUN: %s (%s)", wg.tunName, wg.tunAddress)

	return nil
}

func (wg *MiniWG) setupUDP() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", wg.listenPort))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP socket: %v", err)
	}

	wg.udp = conn
	log.Printf("UDP socket listening on port %d", wg.listenPort)
	return nil
}

func (wg *MiniWG) setupTUN() error {
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: wg.tunName,
		},
	}

	iface, err := water.New(config)
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %v", err)
	}

	wg.tun = iface
	log.Printf("TUN interface %s created", iface.Name())

	// Automatically configure IP address (like wg-quick does)
	if wg.tunAddress != "" {
		log.Printf("Configuring IP address %s on %s", wg.tunAddress, iface.Name())

		// Add IP address: ip addr add 192.168.241.1/24 dev wg0
		cmd := exec.Command("ip", "addr", "add", wg.tunAddress, "dev", iface.Name())
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add IP address %s to %s: %v", wg.tunAddress, iface.Name(), err)
		}

		// Bring interface up: ip link set wg0 up
		cmd = exec.Command("ip", "link", "set", iface.Name(), "up")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to bring up interface %s: %v", iface.Name(), err)
		}

		log.Printf("Interface %s configured with %s and brought up", iface.Name(), wg.tunAddress)
	} else {
		log.Printf("No TUN address specified - interface created but not configured")
	}

	return nil
}