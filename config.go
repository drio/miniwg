package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
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
			privateKeyBytes, err := hex.DecodeString(value)
			if err != nil {
				return fmt.Errorf("failed to decode private key: %v", err)
			}
			copy(wg.privateKey[:], privateKeyBytes)

		case "PeerPublicKey":
			peerKeyBytes, err := hex.DecodeString(value)
			if err != nil {
				return fmt.Errorf("failed to decode peer key: %v", err)
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
	log.Printf("TUN interface %s created", wg.tunName)
	log.Printf("Configure with: ip addr add %s dev %s && ip link set %s up", wg.tunAddress, wg.tunName, wg.tunName)
	return nil
}