# Makefile for MiniWG peer-to-peer testing
#
RAVEN_IP = 192.168.8.43
FWORK_IP = 192.168.8.64

all: 
	@cat Makefile

clean:
	rm -f ./miniwg

# Build the MiniWG binary
build:
	cd .. && go build -o tests/miniwg .

# Start peer1
peer1: build
	sudo ./miniwg -c peer1.conf | tee log1.txt

# Start peer2
peer2: build
	sudo ./miniwg -c peer2.conf | tee log2.txt

# Start both peers
start: build
	sudo ./miniwg -c peer1.conf &
	sleep 1
	sudo ./miniwg -c peer2.conf &
	@echo "Both peers started"

# Test connectivity with netcat server (run in peer2 terminal)
server:
	nc -l 192.168.241.2 8080

# Test connectivity with netcat client (run in peer1 terminal)
client:
	nc -s 192.168.241.1 192.168.241.2 8080

# Test unencrypted traffic on physical interfaces
server-plain:
	nc -l $(FWORK_IP) 8080

client-plain:
	nc $(FWORK_IP) 8080

# Debug commands
test-connectivity:
	ping -c 3 $(FWORK_IP)

check-firewall:
	sudo ufw status | grep 8080

check-listening:
	ss -tuln | grep 8080

# Python HTTP server for testing
http-server:
	python3 -m http.server 8080 --bind $(FWORK_IP)

# Network debugging
debug-network:
	@echo "=== Network Interfaces ==="
	ip addr show | grep -A2 -B2 "192.168.8"
	@echo "=== Routing Table ==="
	ip route show | grep "192.168.8"
	@echo "=== ARP Table ==="
	arp -a | grep "192.168.8"
	@echo "=== Firewall Status ==="
	sudo ufw status

# Stop all peers
stop:
	-pkill -f miniwg

# Open firewall for WireGuard ports and test port
firewall-open:
	sudo ufw allow 51820/udp comment "MiniWG peer1"
	sudo ufw allow 51821/udp comment "MiniWG peer2"
	sudo ufw allow 8080/tcp comment "MiniWG test server"

# Close firewall for WireGuard ports and test port
firewall-close:
	sudo ufw delete allow 51820/udp
	sudo ufw delete allow 51821/udp
	sudo ufw delete allow 8080/tcp

# Capture plaintext traffic with hex dump
capture-plain:
	sudo tcpdump -Ai any -X -s 0 port 8080

# Capture encrypted WireGuard traffic with hex dump
capture-encrypted:
	sudo tcpdump -Ai any -X -s 0 'port 51820 or port 51821'

# Create tmux session with 6 panes in 3x2 grid
tmux: build
	tmux split-window -h
	tmux split-window -h
	tmux split-window -v
	tmux select-pane -L
	tmux split-window -v
	tmux select-pane -L
	tmux split-window -v
	tmux select-layout tiled

.PHONY: build peer1 peer2 start ping stop tmux capture-plain capture-encrypted
