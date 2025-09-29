miniwg is my implementation of the wireguard protocol that I created for learning purposes. 

1. mini-to-mini:

demo/
make tmux

Left panels (raven):
    - make firewall-open; make peer1
    - .. wait for server; make client
    - make capture-tun

Right panels (fwork):
    - make firewall-open; make peer2
    - make server
    - make cpature-udp

