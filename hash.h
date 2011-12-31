#ifndef __HASH__
#define __HASH__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qsheff_parser.h"

#define NUM_HASH 5381
#define CDB_HASHSTART 5381
#define RECVFROM 16
#define MAIL 256
#define SUBJECT 256

typedef struct IP_bucket IP_bucket;
struct IP_bucket {
	char src;
        char IP[RECVFROM];
        IP_bucket *next;
};
IP_bucket* IP_bucket_arr[NUM_HASH];


typedef struct bucket bucket;
struct bucket {
	char mail[MAIL];
	char subject[SUBJECT];
	char recvfrom[RECVFROM];
	int count;
	int is_spammer;
	bucket *next;
};
bucket* bucket_arr[NUM_HASH];

extern unsigned int
cdbhash(char *buf, unsigned int len);

extern void
hash_add(const char *subject, const char *recvfrom, const char *mail, unsigned int h);

extern void
hash_IP(const char *IP, char src, unsigned int h);

extern bucket*
hash_lookup(const char *target, unsigned int h);

extern int 
hash_lookup_IP(const char *target, unsigned int h);

extern void
free_hash_tables(void);


#endif
