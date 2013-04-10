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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

// some OS need this, some not?
#ifndef _USER_SIGNAL_H
#include <signal.h>
#endif


#include "no_key.h"

// Client-side no_key Shamir protocol. This program is just a demo
// of the server 'no_key_server' at work: given a password as argument, 
// it performs the whole three way protocol against that server
// showing the successive steps.
// 
// To do so, the program calls the 'sever' three times, with different
// number of arguments:
//
// 1) No arguments:
//    The server returns a string composed of a temporary filename
//    a space and a bignum prime p as an hex string
//
// 2) two arguments:
//    fname: a temporary filename
//    q1:    an hex string (bignum)
//
//    The server reads p from the temporary filename (or fails),
//    computes a random u2 = 1 mod(p-1), computes q2 = q1^u2 mod(p),
//    stores p and u2 in the temporary filename and
//    prints a string like in 1), but using q2
//
// 3) three arguments:
//    fname: a temporary filename
//    q3:    a hex string (bignum)
//    end:   anything (just to state that we are at the end)
//
//   The server reads p and u2 from the temporary filename (or fails),
//   computes v2 = (1/u2) mod(p-1), computes k = q3^v2 mod(p),
//   UNLINKs the temporary file 
//   and prints the result of BN_bn2bin(k) as a string. 
//   As stated, the last parameter is just a flag to tell the 
//   server this is the last stage.


// Simple utility. Used for 'showing' the innards of the protocol
void print_prime(char *str, BIGNUM *p) {

        printf("%s: [", str);
        BN_print_fp(stdout, p);
        printf("]\n");

        return;
}



int main(int argc, char *argv[], char *envp[]) {

        if(argc <= 1){
                printf("Usage: no_key_client KEY\n");
                exit(-1);
        }

        BIGNUM *p   = BN_new();
        BIGNUM *u1  = BN_new();
        BIGNUM *v1  = BN_new();
        BIGNUM *K   = BN_new();
        BIGNUM *q1  = BN_new();
        BIGNUM *q2  = BN_new();
        BIGNUM *q3  = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        char *filename, *tmp;

        // we are doing forks and pipes
        int pid;
        int pd[2];

        // 'command-name' and parameters for the pipe
        char *params;
        char *command;

        //prevent zombies:
        signal(SIGCHLD, SIG_IGN);

        // ECALLOC is a macro in 'no_key.h' (Calloc with error check)
        ECALLOC(params, char, NO_KEY_MSG_LEN);
        ECALLOC(command, char, 2046);
        ECALLOC(tmp, char, NO_KEY_MSG_LEN + 1);

        // Stage 1)
        //     Call the server with no arguments:
        if(pipe(pd) == -1){
                err(-2, "Pipe error");
        }

        if((pid = fork()) < 0 ){
                err(-2, "Fork error");
        }

        if(pid == 0){ 
                // child
                // close pipe and duplicate stdin on pd[1]
                close(pd[0]);
                dup2(pd[1],1);
                
                // run the server with NO arguments
                execl("./no_key_server", "./no_key_server", NULL);

                // should never happen
                err(-1, "execl error!");
        }

        // From now on, read from the pipe
        ECALLOC(filename, char, FILENAME_MAX);
        close(pd[1]);

        read(pd[0], command, NO_KEY_MSG_LEN);
        close(pd[0]);

        // We [should] get a filename and a BIGNUM as an hex string:
        sscanf(command,"%s %s\n",filename, tmp);

        // argv[1] is the string to be sent (usually a password)
	BN_bin2bn((unsigned char *)argv[1], strlen(argv[1]), K);
        BN_hex2bn(&p, tmp);  

        print_prime("K: ", K);
        print_prime("p: ", p);

        // Step 1 of the protocol:
        //    choose a random exponent mod(p-1) and compute
        //    q1 = K^u1 mod(p)
        //
        u1 = no_key_random_exponent(p);
        BN_mod_exp(q1, K, u1, p, ctx);

        print_prime("u1: ", u1);
        print_prime("q1: ", q1);


        // Stage 2)
        //     Call the server with two arguments:
        //      argv[1]: filename (which was received previously)
        //      argv[2]: q1 as an hex string
        //
        if(pipe(pd) == -1){
                err(-3,"Unable to open pipe\n");
        };
        if((pid = fork()) < 0 ){
                err(-2, "Fork error");
        }

        if(pid == 0){ //child
                close(pd[0]);
                dup2(pd[1],1);

                tmp = BN_bn2hex(q1);
                
                //call the server with 2 args
                execl("./no_key_server", "./no_key_server", filename, tmp, NULL);

                // should never happen
                err(-3, "error!\n");
        }
  
        close(pd[1]);


        ECALLOC(command, char, 65536);
        ECALLOC(tmp, char, NO_KEY_SIZE + 1);
        ECALLOC(filename, char, FILENAME_MAX+1);

        read(pd[0], command, NO_KEY_MSG_LEN);
        close(pd[0]);

        // We [should] get a filename and a BIGNUM as an hex string again
        sscanf(command, "%s %s\n", filename, tmp);
        BN_hex2bn(&q2, tmp);

        // Step 3) of the protocol:
        //    Compute v1 = 1/u1 mod(p-1) and
        //    q3 = q2 ^ v1 mod(p)
        //    Send q3 to the server (together with the filename, as this client-server
        //         example is not connection-oriented)
        //
        v1 = no_key_inverse(u1, p);
        BN_mod_exp(q3, q2, v1, p, ctx);

        print_prime("Q2: ", q2);
        print_prime("Q3: ", q3);

        if(pipe(pd) == -1){
                err(-3,"Unable to open pipe\n");
        };
        if((pid = fork()) < 0 ){
                err(-2, "Fork error");
        }

        if(pid == 0){ //child
                close(pd[0]);
                dup2(pd[1],1);
                tmp = BN_bn2hex(q3);
                // last '1' is to tell the server we are at the last stage.
                // Otherwise it would send to all the USA & China... the very password
                execl("./no_key_server", "./no_key_server", filename, tmp, "1", NULL);
                err(-3, "error!\n");
        }

        ECALLOC(tmp, char, NO_KEY_MSG_LEN + 1);
        // the sample server printfs the unencrypted password: fetch it and output it
        //
        //read(pd[0], tmp, 1);
        read(pd[0], tmp, NO_KEY_MSG_LEN);
        printf("Key: [%s]\n", tmp);
        close(pd[0]);

        return(0);

}
