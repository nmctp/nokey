/* Copyright (c) 2008, Pedro Fortuny Ayuso (info@pfortuny.net) and */
/* Rafael Casado Sánchez (rafacas@gmail.com), */

/* Permission to use, copy, modify, and/or distribute this software for any */
/* purpose with or without fee is hereby granted, provided that the above */
/* copyright notice and this permission notice appear in all copies. */

/* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES */
/* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF */
/* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL ANY OF THE AUTHORS BE LIABLE FOR */
/* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES */
/* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN */
/* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF */
/* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#define NO_KEY_MAX_SIZE 2048

// this probably ought to be run-time configurable
#define NO_KEY_SIZE 1024

#define NO_KEY_TMP_DIR "/tmp/"
#define NO_KEY_CONF_FILE "/etc/no_key.mod"
#define NO_KEY_TMP_TEMPLATE "no_key_XXXXXXXX"
#define NO_KEY_PORT 7771

//notice the 'space', the 'hexadecimal' and the '\0' and 1 more 
// and some extra space
#define NO_KEY_MSG_LEN FILENAME_MAX + 1 + NO_KEY_SIZE/4 + 1 + 10

// error messages
#define NO_KEY_NO_PRIME 5

// easy with calloc's...
#define ECALLOC(x,t,s)                                  \
        if( ((x) =                                      \
             ((t *) calloc((s), sizeof(t)))) == NULL)	\
                err(1, "Calloc error.\n");

// function declarations

BIGNUM * no_key_init();

BIGNUM * no_key_random_exponent(const BIGNUM *); 

BIGNUM * no_key_crypt(BIGNUM *, const BIGNUM *, BIGNUM *);

BIGNUM * no_key_inverse(BIGNUM *, BIGNUM *);
