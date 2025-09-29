package tun

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"github.com/songgao/water"
)

// TUNDevice interface for TUN devices - allows mocking for tests
type TUNDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// validateInterfaceName validates that an interface name is safe for command execution
// Prevents command injection by ensuring only alphanumeric characters and limited special chars
func validateInterfaceName(name string) error {
	// Allow alphanumeric, hyphens, underscores, and dots (common in interface names)
	validName := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid interface name: %s (contains unsafe characters)", name)
	}
	// Additional length check
	if len(name) > 16 { // IFNAMSIZ is typically 16 on Linux
		return fmt.Errorf("interface name too long: %s (max 16 chars)", name)
	}
	return nil
}

// validateTUNAddress validates that a TUN address is a valid CIDR and safe for commands
func validateTUNAddress(address string) error {
	// Parse as CIDR to ensure it's a valid IP/netmask combination
	_, _, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("invalid TUN address: %s (%v)", address, err)
	}
	// Additional safety: ensure no shell metacharacters
	if strings.ContainsAny(address, ";|&$`(){}[]\\\"'<>*?") {
		return fmt.Errorf("TUN address contains unsafe characters: %s", address)
	}
	return nil
}

// SetupTUN creates and configures a TUN interface
func SetupTUN(tunName, tunAddress string) (TUNDevice, error) {
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: tunName,
		},
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %v", err)
	}

	log.Printf("TUN interface %s created", iface.Name())

	// Automatically configure IP address (like wg-quick does)
	if tunAddress != "" {
		// Validate inputs to prevent command injection (gosec G204)
		if err := validateTUNAddress(tunAddress); err != nil {
			return nil, fmt.Errorf("security validation failed: %v", err)
		}
		if err := validateInterfaceName(iface.Name()); err != nil {
			return nil, fmt.Errorf("security validation failed: %v", err)
		}

		log.Printf("Configuring IP address %s on %s", tunAddress, iface.Name())

		// Add IP address: ip addr add 192.168.241.1/24 dev wg0
		// #nosec G204 -- inputs validated above to prevent injection
		cmd := exec.Command("ip", "addr", "add", tunAddress, "dev", iface.Name())
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to add IP address %s to %s: %v", tunAddress, iface.Name(), err)
		}

		// Bring interface up: ip link set wg0 up
		// #nosec G204 -- inputs validated above to prevent injection
		cmd = exec.Command("ip", "link", "set", iface.Name(), "up")
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to bring up interface %s: %v", iface.Name(), err)
		}

		log.Printf("Interface %s configured with %s and brought up", iface.Name(), tunAddress)
	} else {
		log.Printf("No TUN address specified - interface created but not configured")
	}

	return iface, nil
}
