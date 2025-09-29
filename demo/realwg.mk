# Real WireGuard specific targets and variables
#
# This file contains targets for interoperability testing with real WireGuard

# WireGuard command paths
WGQ = /home/linuxbrew/.linuxbrew/bin/wg-quick
WG = /home/linuxbrew/.linuxbrew/bin/wg

# Start real WireGuard as peer2
real-wg-up:
	sudo $(WGQ) up $(PWD)/realwg/real-wg.conf
	@echo "Real WireGuard started - interface wg0 with IP 192.168.241.2"

# Stop real WireGuard only
real-wg-down:
	-sudo $(WGQ) down $(PWD)/realwg/real-wg.conf 2>/dev/null || true

# Show WireGuard status
wg-status:
	sudo $(WG) show