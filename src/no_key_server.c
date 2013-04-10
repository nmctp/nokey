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
#include <signal.h>
#include <err.h>

#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "no_key.h"
#include "no_key_server.h"


// Server-side no_key Shamir protocol. There are three different uses:
//
// 1) No arguments:
//    The server prints a string composed of a temporary filename,
//    a comma and a bignum prime p as a hex string
//
// 2) two arguments:
//    fname: a temporary filename
//    q1:    a hex string (bignum)
//
//    The server reads p from the temporary filename (or fails),
//    computes a random u2 = 1 mod(p-1), computes q2 = q1^u2 mod(p),
//    stores p and u2 in the temporary filename and
//    prints a string like in 1), but the bignum is q2.
//
// 3) three arguments:
//    fname: a temporary filename
//    q3:    a hex string (bignum)
//    end:   anything (just to state that we are at the end)
//
//   The server reads p and u2 from the temporary filename (or fails),
//   computes v2 = (1/u2) mod(p-1), computes k = q3^v2 mod(p),
//   UNLINKs the temporary file 
//   and prints the result of BN_bn2bin(k) as a string

//TODO:
//
// Should be aware of the stage the protocol is at, otherwise it can
// be fooled to send the password back. how?...
//
// Different status depending on different possible errors
//

// Server options:
// -c filename: use a different configuration file (/etc/no_key.key)
// -t dirname:  use a different "temporary" directory (/tmp)
// -p string:   fix prime number to 'p'. Overrides -c
//              because the conf. file contains only the prime number
// -s:          run as a server *on localhot* 
// -P port:     port to listen on (7771) 

int main(int argc, char **argv) {

        char *config   = NO_KEY_CONF_FILE;
        char *template;
        char *tempdir  = NO_KEY_TMP_DIR;
        char *p_hex    = "01";

        FILE *config_file;

        char *tmp;
        char opt;

        int daemon = 0;
        int port   = NO_KEY_PORT;

        BIGNUM *p   = BN_new();
        BN_CTX *ctx = BN_CTX_new();


        extern char *optarg;
        extern int optind;
        extern int optopt;
        extern int opterr;
        extern int optreset;

        while((opt = getopt(argc, argv, NO_KEY_OPTS)) != -1){
                switch(opt) {
                case 's':
                        daemon  = 1;
                        break;

                case 't':
                {
                        struct stat *sb;
                        ECALLOC(sb,struct stat, 1);
                        stat(optarg, sb);
                        if(sb->st_mode == S_IFDIR)
                                tempdir = optarg;
                        else
                                warnx("%s is not a directory, using %s.", optarg, tempdir);
                        break;
                }

                case 'p':
                        p_hex   = optarg;
                        BN_hex2bn(&p, p_hex);
                        if(BN_is_prime(p, BN_prime_checks, 
                                       NULL, ctx, NULL) == 0){
                                fprintf(stderr, 
                                        "Sorry, the specified modulus [%s] "\
                                        "is not prime\n", p_hex);
                                exit(NO_KEY_NO_PRIME);
                        }
                        break;

                case 'c':
                        config  = optarg;
                        break;

                case 'P':
                        port    = atoi(optarg);
                        break;

                case 'h':
                default:
                        usage();
                }
        }
        argc -= optind;
        argv += optind;

        // If the config file is readable, get the modulus from it
        if((config_file = fopen(config, "r")) != NULL){
                ECALLOC(p_hex, char, NO_KEY_SIZE);
                fscanf(config_file, "%s\n", p_hex);
                fclose(config_file);
                BN_hex2bn(&p, p_hex);
        } 


        // the non-readable case is dealt with in the next if sentence
        // If argc == 0 we NEEDS the modulus
        //    (otherwise we shall read it from the session file).
        // So:
        // If p has not been specified (p_hex == "01"), generate it.
        //
        if(argc == 0 && strcmp(p_hex, "01") == 0){
                p = no_key_init();

                // If we are here it is because the config file does not exist
                // (or is not readable). Try to create it and write p in it,
                // to prevent future generations of p, which are expensive
                if((config_file = fopen(config,"w")) != NULL){
                        ECALLOC(tmp, char, NO_KEY_SIZE+1);
                        tmp = BN_bn2hex(p);
                        fprintf(config_file, "%s\n", tmp);
                        fclose(config_file);
                } // else:
                // we may be unable to write to open file, but this is 
                // "irrelevant", because from now on, both the prime and the 
                // rest of parameters are read from the session file. The
                // "write to file" utility is just a convenience,
                // not a requirement.                
        }


        if(daemon) {
                BIGNUM *u2  = BN_new();
                BIGNUM *v2  = BN_new();
                BIGNUM *q1  = BN_new();
                BIGNUM *q2  = BN_new();
                BIGNUM *q3  = BN_new();
                BIGNUM *q4  = BN_new();

                struct sockaddr_in addr, client_addr;
                int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                int client;

                int optval = 1;
                unsigned int optlen = sizeof(optval);
                unsigned int client_addr_len = sizeof(client_addr);

                memset(&addr, 0, sizeof(addr));

                client_addr_len = sizeof(client_addr);
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                if(setsockopt(sock, SOL_SOCKET, 
                              SO_REUSEADDR, &optval, optlen) == -1){
                        perror("Cannot set options on socket");
                }
    
                if(bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1){
                        perror("Cannot bind the socket");
                }

                if(listen(sock, 10)==-1){
                        perror("Cannot create the socket");
                }

                //prevent zombies:
                signal(SIGCHLD, SIG_IGN);

                while((client = accept(sock, 
                                       (struct sockaddr *) &client_addr,
                                       &client_addr_len)) != -1){
                        int pid;
                        if((pid = fork())==-1){
                                perror("Unable to fork().\n");
                                exit(1);
                        }

                        switch(pid){
                                //child
                        case 0: 
                                //close copy of the server
                                close(sock);

                                char *buffer, *echo;
                                ECALLOC(buffer, char, NO_KEY_MSG_LEN);
                                ECALLOC(tmp, char, NO_KEY_MSG_LEN);
                                ECALLOC(echo, char, NO_KEY_MSG_LEN);
		
                                tmp = BN_bn2hex(p);
                                snprintf(echo, NO_KEY_MSG_LEN, "%s\n", tmp);
	
                                // step 0: send modulus
                                send(client, echo, strlen(echo), 0);
                                memset(echo, 0, NO_KEY_MSG_LEN);
                                memset(buffer, 0, NO_KEY_MSG_LEN);

                                // step 2: 
                                // receive q1 = exp_mod(k, u1, p)
                                // compute u2 (unit modulo p-1)
                                // send    q2 = exp_mod(q1, u2, p)
                                recv(client, buffer, NO_KEY_MSG_LEN, 0);
                                BN_hex2bn(&q1, buffer);
                                u2 = no_key_crypt(q2, q1, p);
                                tmp = BN_bn2hex(q2);
                                snprintf(echo, NO_KEY_MSG_LEN, "%s\n", tmp);
                                send(client, echo, strlen(echo), 0);

                                memset(echo, 0, NO_KEY_MSG_LEN);
                                memset(buffer, 0, NO_KEY_MSG_LEN);
	
                                // step 3:
                                // receive q3 = exp_mod(q2, 1/u1, p)
                                // compute q4 = exp_mod(q3, 1/u2, p)
                                // PRINT (NOT SEND BACK!!!!) q4 as a binary string: the key
                                recv(client, buffer, NO_KEY_MSG_LEN, 0);
                                BN_hex2bn(&q3, buffer);
                                v2 = no_key_inverse(u2, p);
                                BN_mod_exp(q4, q3, v2, p, ctx);

                                free(tmp);
                                ECALLOC(tmp, char, NO_KEY_MSG_LEN);
                                BN_bn2bin(q4, (u_char *)tmp);

                                send(client, tmp, NO_KEY_SIZE, 0);
                                printf("[%s]\n", tmp);
                                exit(0);

                                //parent
                        default:
                                waitpid(pid, (int *)0, WNOHANG);
                                close(client);
                        }
                }
                perror("Unable to accept connections.\n");
                exit(0);    
        }

        // no daemon: we are running inside a wrapper, [probably]
        // give different answers according to the number of parameters
        //
        // 0: send the session filename and p
        //
        // 2: (we have been sent a session name and a number q1),
        //    return the session name and q2
        //
        // 3: (we have been sent a session name and a number q3),
        //    return q4 in binary format, which **should be** the key.

        switch(argc){
        case 0:
                ECALLOC(template, char, FILENAME_MAX + 1);
                strncpy(template, tempdir, FILENAME_MAX);
                strncat(template, 
                        NO_KEY_TMP_TEMPLATE, 
                        FILENAME_MAX - strlen(template));

                tmp = first_step(template, p);

                printf("%s\n", tmp);
                return(0);

        case 2:
                tmp = second_step(argv[0], argv[1]);

                printf("%s\n", tmp);
                return(0);

        case 3:
                tmp = third_step(argv[0], argv[1]);

                printf("%s", tmp);
                return(0);

        default:
                printf("Wrong number of arguments.\n");
                usage();
                return(-1);                
        }
}


void usage(){
        char * usage = "\n\
\n\
-c filename: set a different configuration file (/etc/no_key.key)\n\
-t dirname:  set a different 'temporary' directory (/tmp)\n\
-p string:   fix prime number to 'p'. Overrides -c\n\
             because the configuration file contains only the prime number.\n\
-s:          run as a server listening *on localhot*.\n\
\n\
-P port:     port to listen on (7771). Only useful with -s";

        printf("(C) 2008-2010 Pedro Fortuny Ayuso & Rafael Casado Sanchez\n");
        printf("no_key_server options:");
        printf("%s\n", usage);
  
        exit(0);
}




// first step: create temporary file and fix prime number  
char * first_step(char *template, BIGNUM *p){
        char *tmp, *answer;
        int session, len;

        ECALLOC(tmp, char, NO_KEY_SIZE + 1);
        tmp = BN_bn2hex(p);

        ECALLOC(answer, char, NO_KEY_MSG_LEN);

        if(strlen(template)>0){
                if((session = mkstemp(template)) == -1) {
                        perror("Unable to create temporary file.\n");
                        exit(1);
                }
    
                if(write(session, tmp, strlen(tmp)) != strlen(tmp)){
                        perror("Unable to write into the temporary file.\n");
                        exit(1);
                }

                len = NO_KEY_MSG_LEN;
                snprintf(answer, len, "%s %s\n", template , BN_bn2hex(p));

                close(session);
        } else {
                len = NO_KEY_SIZE/4 +1;
                snprintf(answer, len, "%s\n", BN_bn2hex(p));
        }
  
        return(answer);
}

// second step: compute the powers
//    fname: a temporary filename
//    q1:    a hex string (bignum)
//
//    The server reads p from the temporary filename (or fails),
//    computes a random u2 = 1 mod(p-1), computes q2 = q1^u2 mod(p),
//    stores p and u2 in the temporary filename and
//    prints a string like in 1), but with q2 instead.

char * second_step(char *filename, char *q1_str){

        FILE *file;
        BIGNUM *q1 = BN_new();
        BIGNUM *p = BN_new();
        BIGNUM *u2;
        BIGNUM *q2 = BN_new();

        char *tmp, *hex; // hexadecimal buffers
        char *answer;

        BN_hex2bn(&q1, q1_str);

        // read p from 'filename' (the session file, supposedly)
        file = fopen(filename, "r");
        if((file = fopen(filename, "r")) == NULL) {
                err(-3, "No readable session file with name %s", filename);
        }

        ECALLOC(tmp, char, NO_KEY_SIZE + 1);
        fgets(tmp, NO_KEY_SIZE, file);
        BN_hex2bn(&p,tmp);
        fclose(file);

        // encrypt q1 into q2, u2 is the random unit used to encrypt
        u2 = no_key_crypt(q2, q1, p);
        // write p and u2 into the session file
        if((file = fopen(filename, "w")) == NULL){
                err(-3, "Unable to open %s for writing", filename);
        };

        ECALLOC(hex, char, NO_KEY_SIZE + 1);
        hex = BN_bn2hex(p);
        fprintf(file, hex, strlen(hex));
        fprintf(file, "\n");
        hex = BN_bn2hex(u2);
        fprintf(file, hex, strlen(hex));
        fclose(file);

        // and return the pair 'filename, u2'
        hex = BN_bn2hex(q2);
        ECALLOC(answer, char, NO_KEY_MSG_LEN);
        snprintf(answer, NO_KEY_MSG_LEN, "%s %s\n", filename, hex); 
        return(answer);
}

// 3) three arguments:
//    fname: a temporary filename
//    q3:    a hex string (bignum)
//    end:   anything (just to state that we are at the end)
//
//   The server reads p and u2 from the temporary filename (or fails),
//   computes v2 = (1/u2) mod(p-1), computes k = q3^v2 mod(p),
//   UNLINKs the temporary file 
//   and prints the result of BN_bn2bin(k) as a string

char *third_step(char *filename, char *q3_str){

        FILE *file;
        BIGNUM *q3 = BN_new();
        BIGNUM *q1 = BN_new() ;
        BIGNUM *p = BN_new();
        BIGNUM *u3 = BN_new();
        BIGNUM *q4 = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        char *tmp, *answer;

        BN_hex2bn(&q3, q3_str);

        // get p and q1 from the session file:
        if((file = fopen(filename, "r"))  == NULL) {
                err(-3, "Unable to open %s for writing", filename);
        }

        ECALLOC(tmp, char, NO_KEY_SIZE + 1);    
        fgets(tmp, NO_KEY_SIZE, file);
        BN_hex2bn(&p,tmp);
        fgets(tmp, NO_KEY_SIZE, file);
        BN_hex2bn(&q1,tmp);
        fclose(file);

        // decrpyt q3, using q1^(-1) mod(p)
        u3 = no_key_inverse(q1, p);
        BN_mod_exp(q4, q3, u3, p, ctx);

        // answer
        ECALLOC(answer, char, NO_KEY_MSG_LEN);
        BN_bn2bin(q4, (u_char *)answer);
        if(unlink(filename) == -1){
                warn("Unable to erase session file %s", filename);
        };

        return(answer);
}
