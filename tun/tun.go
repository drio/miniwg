package tun

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/songgao/water"
)

// TUNDevice interface for TUN devices - allows mocking for tests
type TUNDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
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
		log.Printf("Configuring IP address %s on %s", tunAddress, iface.Name())

		// Add IP address: ip addr add 192.168.241.1/24 dev wg0
		cmd := exec.Command("ip", "addr", "add", tunAddress, "dev", iface.Name())
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to add IP address %s to %s: %v", tunAddress, iface.Name(), err)
		}

		// Bring interface up: ip link set wg0 up
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
