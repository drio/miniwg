# Common Makefile definitions for MiniWG demo scenarios
#
# This file contains shared variables and targets used by all demo Makefiles.

# Shared variables
BINARY = ../miniwg

# Common targets
all:
	@cat Makefile

clean:
	rm -f $(BINARY)
	rm -f *.log