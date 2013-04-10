# Copyright (c) 2008, Pedro Fortuny Ayuso (info@pfortuny.net) and
# Rafael Casado Sánchez (rafacas@gmail.com),

# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.

# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL ANY OF THE AUTHORS BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

CC=gcc
CC_OPTS=-DDEBUG -g -O2  -Wall -Wno-sign-compare -fsigned-char
LIBS=-lcrypto -lssl

default: no_key no_key_client no_key_server 
	@echo
	@echo Successful build.
	@echo

clean:
	rm -f no_key_client no_key_server test no_key.o
	rm -rf *.dSYM
	find . -name "*~" -exec rm -f \{\} \;

no_key_server: no_key no_key_server.*
	@$(CC) $(CC_OPTS) $(LIBS) -o no_key_server no_key_server.c no_key.o

no_key_client: no_key no_key_client.*
	@$(CC) $(CC_OPTS) $(LIBS) -o no_key_client no_key_client.c no_key.o

no_key: no_key.*
	@$(CC) $(CC_OPTS) -c no_key.c -o no_key.o

test: no_key_client
	./no_key_client 'Teh passwrod!'
	@echo
	@echo
	@echo "Try ./no_key_client your_password"
	@echo
