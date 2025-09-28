package config

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// Config holds WireGuard configuration
type Config struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
	PeerKey    [32]byte
	LocalIndex uint32
	PeerAddr   *net.UDPAddr
	ListenPort int
	TunName    string
	TunAddress string
}

// LoadConfig reads and parses a WireGuard configuration file
func LoadConfig(configFile string) (*Config, error) {
	// Validate and clean the config file path to prevent directory traversal
	cleanPath := filepath.Clean(configFile)

	// Ensure the path doesn't contain directory traversal attempts
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid config file path: directory traversal not allowed")
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	config := &Config{
		LocalIndex: 0x12345678, // Default local index
	}

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
				return nil, fmt.Errorf("failed to decode private key: %v", err)
			}
			if len(privateKeyBytes) != 32 {
				return nil, fmt.Errorf("private key must be 32 bytes")
			}
			copy(config.PrivateKey[:], privateKeyBytes)

		case "PeerKey":
			peerKeyBytes, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("failed to decode peer key: %v", err)
			}
			if len(peerKeyBytes) != 32 {
				return nil, fmt.Errorf("peer key must be 32 bytes")
			}
			copy(config.PeerKey[:], peerKeyBytes)

		case "ListenPort":
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid listen port: %v", value)
			}
			config.ListenPort = port

		case "PeerEndpoint":
			addr, err := net.ResolveUDPAddr("udp", value)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve peer endpoint: %v", err)
			}
			config.PeerAddr = addr

		case "TunName":
			config.TunName = value

		case "TunAddress":
			config.TunAddress = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	// Validate required configuration values
	var missing []string

	if config.PrivateKey == [32]byte{} {
		missing = append(missing, "PrivateKey")
	}
	if config.PeerKey == [32]byte{} {
		missing = append(missing, "PeerKey")
	}
	if config.ListenPort == 0 {
		missing = append(missing, "ListenPort")
	}
	if config.PeerAddr == nil {
		missing = append(missing, "PeerEndpoint")
	}
	if config.TunName == "" {
		missing = append(missing, "TunName")
	}
	if config.TunAddress == "" {
		missing = append(missing, "TunAddress")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required configuration values: %v", missing)
	}

	// Generate public key from private key
	curve25519.ScalarBaseMult(&config.PublicKey, &config.PrivateKey)

	return config, nil
}
