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

#include <openssl/bn.h>
#include <openssl/rand.h>
#include "no_key.h"

// NO_KEY_SIZE is hardcoded, should become configurable in a future release

BIGNUM *no_key_init() {
        BIGNUM *ret = BN_new();

        // We use urandom. This is actually irrelevant because the modulus is
        // made public. But is quite slooooooooooooooow
        RAND_load_file("/dev/random", NO_KEY_SIZE);
        BN_generate_prime(ret, NO_KEY_SIZE, 1, NULL, NULL, NULL, NULL);
        return(ret);
}


BIGNUM *no_key_random_exponent(const BIGNUM *p) {
// Given a modulus p (prime), generate a random number u coprime with (p-1)
// (so that it is an 'invertible' exponent modulo p)
// 
// Input: BIGNUM * p (should be prime, but no check is done)
//
// Return value: BIGNUM * u, a random exponent.
//
// For randomness, this function uses BN_rand, so it is as random as that,
// (and as per man 3 BN_rand: 'generates a cryptographically strong pseudo-
// random number...' whatever that means).

        BIGNUM *unit = BN_new();
        BIGNUM *two  = BN_new();
        BIGNUM *p_1  = BN_new();
        BIGNUM *gcd  = BN_new();
        BN_CTX *ctx  = BN_CTX_new();

        BN_set_word(two, 2);
        BN_sub(p_1, p, BN_value_one());

        // unit has nonzero most significant bit and is odd
        BN_rand(unit, NO_KEY_SIZE, 0, 1);

        // mostly harmless...
        BN_mod(unit, unit, p_1, ctx);
        
        // Add 2 to u until gcd(u, p-1) == 1.
        // There is probably a better way (anyone out there?)
        BN_gcd(gcd, unit, p_1 ,ctx);
        while(BN_ucmp(gcd, BN_value_one())!=0){//!(BN_is_one(gcd))
                BN_add(unit, unit, BN_value_one());
                BN_gcd(gcd, unit, p_1 ,ctx);
        }

        // use a number 'modulo p', which is the realm we are in.
        // the test above prevents unit from being either p-1
        // or 1, which would be wrong.
        BN_mod(unit, unit, p, ctx);

        // mostly harmless...
        BN_CTX_free(ctx);
        return(unit);
}


BIGNUM * no_key_crypt(BIGNUM *res, const BIGNUM *msg,  BIGNUM *p){
// Encrypt 'msg' using a random unitary u exponent mod(p-1) by doing
//
// res = msg^u mod(p)
//
// res is assigned the value of the encryption
//
// Input: 
//    res: an allocated (BN_new) BIGNUM *
//    msg: a BIGNUM * (the msg to be encrypted) 
//      p: a BIGNUM * (the modulus of the no key protocol)
//
// Return value:
//    BIGNUM *: the exponent u (will be needed afterwards...)
//
// Side Effect: [important]
//    res: *res is given the value of the encryption [res = msg^u mod(p)]

        BIGNUM *exponent = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        exponent = no_key_random_exponent(p);

        // prevent 'little' exponents
        while(BN_num_bits(exponent) < BN_num_bits(p) - 1)
                exponent = no_key_random_exponent(p);
        
        BN_mod_exp(res, msg, exponent, p, ctx);
  
        // mostly harmless...
        BN_CTX_free(ctx);
        return (exponent);
}


BIGNUM * no_key_inverse(BIGNUM *u, BIGNUM *p){
// Compute the reciprocal of a BIGNUM *u modulo (p-1).
//
// Input:
//   u: a BIGNUM * (the number whose inverse is to be computed)
//   p: a BIGNUM * (the modulus of the no key protocol)
//
// Return value:
//   BIGNUN *: the inverse of u modulo (p-1) if it exists,
//             [otherwise, NULL]
//
// (this is a utility function: the operation is cumbersome and
//  is performed several times)

        BIGNUM *res = BN_new();
        BIGNUM *p_1 = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        BN_sub(p_1, p, BN_value_one());

        // this is the actual operation:
        BN_mod_inverse(res, u, p_1, ctx);

        BN_CTX_free(ctx);
        return(res);
}
