#include "hash.h"

static unsigned int
set_hash(unsigned int h, unsigned char c)
{
        h += (h << 5);
        return h ^ c;
}

extern unsigned int
cdbhash(char *buf, unsigned int len)
{
         unsigned int h;

         h = CDB_HASHSTART;
         while (len) {
                h = set_hash(h, *buf++);
                --len;
         }

         return (h % NUM_HASH);
}

extern void
hash_IP(const char *IP, char src, unsigned int h)
{
        IP_bucket *ip = NULL;

        if (IP_bucket_arr[h] == NULL) {
                if ((IP_bucket_arr[h] = (IP_bucket *) malloc(sizeof(IP_bucket))) == NULL) {
                        fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
                        exit(-1);
                }

                memset(IP_bucket_arr[h]->IP, 0x0, sizeof(IP_bucket_arr[h]->IP));
        }

        ip = IP_bucket_arr[h];

        if(ip->IP[0] == '\0') {
                if ((strncpy(ip->IP, IP, sizeof(ip->IP) - 1)) == NULL) {
                        fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
                        exit(-1);
                }
		ip->src = src;
        }

        else {
                while(ip->next != NULL)
                        ip = ip->next;

                if ((ip->next = (IP_bucket *) malloc(sizeof(IP_bucket))) == NULL){
                        fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
                        exit(-1);
                }

                ip = ip->next;

                if ((strncpy(ip->IP, IP, sizeof(ip->IP) - 1)) == NULL) {
                        fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
                        exit(-1);
                }
		ip->src = src;
        }

        ip->next = NULL;
}


extern void
hash_add(const char *subject, const char *recvfrom, const char *mail, unsigned int h)
{
	bucket *bp = NULL;

	if (bucket_arr[h] == NULL) {
        	if ((bucket_arr[h] = (bucket *) malloc(sizeof(bucket))) == NULL) {
           		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		   	exit(-1);
       		}
		
        	memset(bucket_arr[h]->subject, 0x0, sizeof(bucket_arr[h]->subject));
		memset(bucket_arr[h]->mail, 0x0, sizeof(bucket_arr[h]->mail));
		memset(bucket_arr[h]->recvfrom, 0x0, sizeof(bucket_arr[h]->recvfrom));
	}

	bp = bucket_arr[h];

	if(bp->subject[0] == '\0') {
		if ((strncpy(bp->subject, subject, sizeof(bp->subject) - 1)) == NULL) {
           		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		   	exit(-1);
        	}

		if ((strncpy(bp->mail, mail, sizeof(bp->mail) -  1)) == NULL) {
			fprintf(stderr, "File: %s - Line: %d %s.\n", __FILE__, __LINE__, strerror(errno));
			exit(-1);
		}
     	
		if ((strncpy(bp->recvfrom, recvfrom, sizeof(bp->recvfrom) - 1)) == NULL) {
           		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		   	exit(-1);
        	}
	}
	
	else {
		while(bp->next != NULL)
			bp = bp->next;
	
        	if ((bp->next = (bucket *) malloc(sizeof(bucket))) == NULL){
           		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		   	exit(-1);
        	}
        
		bp = bp->next;
		
        	if ((strncpy(bp->subject, subject, sizeof(bp->subject) - 1)) == NULL) {
           		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		   	exit(-1);
        	}
		
		if ((strncpy(bp->mail, mail, sizeof(bp->mail) -  1)) == NULL) {
			fprintf(stderr, "File: %s - Line: %d %s.\n", __FILE__, __LINE__, strerror(errno));
			exit(-1);
		}
        
        	if ((strncpy(bp->recvfrom, recvfrom, sizeof(bp->recvfrom) - 1)) == NULL) {
           		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		   	exit(-1);
        	}
	}

	bp->count = 1;
	bucket_arr[h]->is_spammer = 0;
	bp->next = NULL;
}

extern bucket*
hash_lookup(const char *target, unsigned int h)
{
	bucket *bp = NULL;
        bp = bucket_arr[h];

        while (bp != NULL) {
                if (! strncmp(bp->subject, target, sizeof(target)))
                        return bp;
                bp = bp->next;
        }

        return NULL;
}

extern int
hash_lookup_IP(const char *target, unsigned int h)
{
        IP_bucket *ip = NULL;
        ip = IP_bucket_arr[h];

        while (ip != NULL) {
                if (! strncmp(ip->IP, target, sizeof(target)))
                        return 1;
                ip = ip->next;
        }

        return 0;
}

extern void
free_hash_tables(void)
{
        int i = 0;
	bucket *bp = NULL, *tmp = NULL;
	IP_bucket *ip = NULL, *tmp_ip = NULL;

	for(i = 0; i < NUM_HASH; i++)
		for(bp = bucket_arr[i]; bp != NULL; ) {
			tmp = bp;
			bp = bp->next;
			free(tmp);
		}

        for(i = 0; i < NUM_HASH; i++)
                for(ip = IP_bucket_arr[i]; ip != NULL; ) {
                        tmp_ip = ip;
                        ip = ip->next;
                        free(tmp_ip);
                }
}
