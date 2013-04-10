#define NO_KEY_DEF_TEMP   "/tmp"
#define NO_KEY_OPTS "st:p:c:P:h"
#define NO_KEY_PORT 7771

char *first_step(char *, BIGNUM *p);
char *second_step(char *, char *);
char *third_step(char *, char *);

void usage();
