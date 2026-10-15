CFLAGS = -std=c11 -g -O2 -Wall -Wextra -ffile-prefix-map=$(CURDIR)=.

confine: confine.c caps.h
	$(CC) $(CFLAGS) -o $@ confine.c

# The capability names come from the kernel header, never from a table
# typed in here. A kernel that adds one is picked up by rebuilding.
caps.h: mkcaps.sh /usr/include/linux/capability.h
	./mkcaps.sh > $@.new && mv $@.new $@

test: confine
	@t/run.sh

clean:
	rm -f confine caps.h caps.h.new

.PHONY: test clean
