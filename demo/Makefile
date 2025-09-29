include common.mk
include realwg.mk

# Override clean to also clean subdirectories
clean:
	rm -f miniwg *.log mini/*.log realwg/*.log

build:
	cd .. && go build -o demo/miniwg .

# ==========================================
# MiniWG vs MiniWG Testing
# ==========================================

# Start peer1
peer1:
	sudo $(BINARY) -c mini/peer1.conf | tee mini/peer1.log

# Start peer2
peer2:
	sudo $(BINARY) -c mini/peer2.conf | tee mini/peer2.log

# ==========================================
# Common Targets
# ==========================================

stop:
	-pkill -f miniwg
	-sudo $(WGQ) down real-wg 2>/dev/null || true

# Open firewall for WireGuard ports and test port
firewall-open:
	sudo ufw allow 51820/udp comment "MiniWG peer1"
	sudo ufw allow 51821/udp comment "MiniWG peer2/Real WG"
	sudo ufw allow 8080/tcp comment "Test server"

# Close firewall for WireGuard ports and test port
firewall-close:
	sudo ufw delete allow 51820/udp
	sudo ufw delete allow 51821/udp
	sudo ufw delete allow 8080/tcp

# Capture plaintext traffic on TUN interfaces
capture-tun:
	sudo tcpdump -Ai any -X -s 0 port 8080

# Capture encrypted WireGuard traffic on UDP ports
capture-udp:
	sudo tcpdump -Ai any -X -s 0 'port 51820 or port 51821'

# Debug network interfaces
debug-network:
	@echo "=== Network Interfaces ==="
	ip addr show | grep -A2 -B2 "192.168.241"
	@echo "=== WireGuard Status ==="
	sudo wg show || echo "No WireGuard interfaces active"

# Test connectivity between peers
ping:
	ping -c 3 -I 192.168.241.1 192.168.241.2

# Test with netcat server (run on peer2 side - 192.168.241.2)
server:
	nc -l 192.168.241.2 8080

# Test with netcat client (run from peer1 side - 192.168.241.1)
client:
	nc -s 192.168.241.1 192.168.241.2 8080

# Create tmux session with multiple panes
tmux: build
	tmux split-window -h
	tmux split-window -v
	tmux select-pane -L
	tmux split-window -v
	tmux select-layout tiled

.PHONY: build clean stop firewall-open firewall-close capture-tun capture-udp debug-network ping server client tmux
.PHONY: peer1 peer2 real-wg-up real-wg-down wg-status