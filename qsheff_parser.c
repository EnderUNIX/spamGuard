#include <stdio.h>
#include "qsheff_parser.h"

extern int w;
extern int b;
extern int p;

extern int
is_ignored_IP(char* IP, char src, unsigned int h)
{
        IP_bucket *ip = NULL;
        ip = IP_bucket_arr[h];

        while (ip != NULL) {
		if (src & ip->src)
	                if (DoMatch(IP, ip->IP, strlen(ip->IP)) == TRUE)
        	                return 1;
                ip = ip->next;
        }
        
	return 0;
}

static void
trim_subj(char* subj)
{
	int i = 0, j = 0, k = 0, l = 0, tag_size = 0, subj_size = 0;
	char* str = NULL;
	char tags[MAX_TRIM_WORDS][VALSIZE];

	for (i = 0; i < MAX_TRIM_WORDS; i++)
		memset(tags[i], 0x0, VALSIZE);

	for (i = 0, j = 0, k = 0; (i < MAX_TRIM_WORDS) && (trim_subj_str[j] != '\0') && (trim_subj_str[j] != '\n') && (trim_subj_str[j] != '\r') && (k < VALSIZE); j++) {
		if (trim_subj_str[j] != ',') {
			tags[i][k] = trim_subj_str[j];
			k++;
		}
		else { i++; k = 0; }
	}

	subj_size = sizeof(subj); /* for not evaluating size of subject in all steps of for loop */
	for (j = 0; j <= i; j++)
		if (strstr(subj, tags[j]) != NULL) {
			tag_size = strlen(tags[j]);
			for (k = 0, l = tag_size; (subj[k] != '\0') && (k < subj_size); k++, l++)
				subj[k] = subj[l];
			subj[k] = '\0';
			return;
		}
}

static void
update_qsheff_rules(void)
{
	int i = 0;
        bucket *bp = NULL;
        FILE *fp = NULL;

        if ((fp = fopen(qsheff_rules_file, "a+")) == NULL) {
                fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
                exit(-1);
        }
		
	if (enable_subj_filt == 2) {
	        for(i = 0; i < NUM_HASH; i++)
        	        for(bp = bucket_arr[i]; bp != NULL; bp = bp->next) {
				if (bp->is_spammer) {
					trim_subj(bp->subject);
					if (strlen(bp->subject) > 0)
						fprintf(fp, "h:(Subject:)(%s)\n", bp->subject);
				}
        	        }
	}

	else {
                for(i = 0; i < NUM_HASH; i++)
                        for(bp = bucket_arr[i]; bp != NULL; bp = bp->next)
                                if (bp->is_spammer)
					if (strlen(bp->subject) > 0)
	                                        fprintf(fp, "h:(Subject:)(%s)\n", bp->subject);
        }
}

extern void 
parse_qsheff_log(const char* logfile)
{
	int i = 0, recv_len = 0, mail_len = 0, sub_len = 0;
	char line[MAXLINE], mail[MAIL], recvfrom[RECVFROM], subject[SUBJECT];
	char *str  = NULL, *tmp  = NULL;
	bucket *bp = NULL;
	FILE *fp = NULL;
	struct stat st;
        hist_stat old;
        hist_stat new;

	memset(mail, 0x0, MAIL);
	memset(line, 0x0, MAXLINE);
	memset(recvfrom, 0x0, RECVFROM);
	memset(subject, 0x0, SUBJECT);

	get_saved_pos(&old);

	if ((fp = fopen(logfile, "r")) == NULL) {
        	fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
    	}

        if ((stat(logfile, &st)) == -1) {
                fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
                exit(-1);
        }

        if (st.st_ino == old.inode)
                if (fseek(fp, old.saved_pos, SEEK_SET) != 0) {
	                fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
        	        exit(-1);
        	}

	while( fgets(line, MAXLINE, fp) ) {
		line[sizeof(line) - 1] = '\0';
		
		if ((tmp = strstr(line, "recvfrom=")) == NULL)
			continue;
		str = tmp + 9;
		recv_len = str - tmp - 9;
		for (i = 0; (*str != ',') && (*str != '\0') && (*str != '\r') && (*str != '\n') && (i < RECVFROM) && ( recv_len++ < RECVFROM ); recvfrom[i] = *str, i++, str++);
		recvfrom[sizeof(recvfrom) - 1] = '\0';	
		
		if ((tmp = strstr(line, "from=`")) == NULL)
			continue;
		str = tmp + 6;
		mail_len = str - tmp - 6;
		for (i = 0; (*str != ',') && (*str != '\0') && (*str != '\r') && (*str != '\n') && (i < MAIL) && ( mail_len++ < MAIL ); mail[i] = *str, i++, str++);
		if (i > 0)
			mail[i - 1] = '\0';

		if ((tmp = strstr(line, "subj=`")) == NULL)
			continue;
		str = tmp + 6;
		sub_len = str - tmp - 6;
		for (i = 0; (*str != ',') && (*str != '\0') && (*str != '\r') && (*str != '\n') && (i < SUBJECT) && ( sub_len++ < SUBJECT ); subject[i] = *str, i++, str++);
		subject[i - 1] = '\0';

		if (((bp = hash_lookup(subject, cdbhash(subject, sizeof(subject)))) != NULL) && (!strncmp(bp->recvfrom, recvfrom, sizeof(bp->recvfrom))))
			bp->count++;

		else
			hash_add(subject, recvfrom, mail, cdbhash(subject, sizeof(subject)));

	    	memset(mail, 0x0, MAIL);
           	memset(line, 0x0, MAXLINE);
            	memset(recvfrom, 0x0, RECVFROM);
            	memset(subject, 0x0, SUBJECT);
		recv_len = mail_len = sub_len = 0;
		bp = NULL;
	}

        new.inode = st.st_ino;
        new.saved_pos = ftell(fp);
        save_pos(&new);
        
	if (fclose(fp) != 0) {
                fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
                exit(-1);
        }
}

extern void
load_ignored_IP(const char* IP_file, char src)
{
        FILE *fp = NULL;
        char line[MAXLINE];

        if ((fp = fopen(IP_file, "r")) == NULL){
                fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
                exit(-1);
        }

	memset(line, 0x0, MAXLINE);

        while( fgets(line, MAXLINE, fp) ) {
                line[sizeof(line) - 1] = '\0';
		removespaces(line, strlen(line));

		if (!hash_lookup_IP(line, cdbhash(line, sizeof(line))))
			hash_IP(line, src, cdbhash(line, sizeof(line)));

                memset(line, 0x0, MAXLINE);
	}

        if (fclose(fp) != 0) {
                fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
                exit(-1);
        }
}

extern int
qsheff_finalize(void)
{
        int i = 0, spamcnt = 0;
        bucket *bp = NULL, *tmp = NULL;
	FILE *fp = NULL;
	char mailbuf[2048];
        
        if ((fp = fopen(badmailfile, "a+")) == NULL) {
		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
        }

	for (i = 0; i < NUM_HASH; i++)
		for (bp = bucket_arr[i]; bp != NULL; bp = bp->next) {
			memset(mailbuf, 0x0, sizeof(mailbuf));
		
			if ((bp->count < bcnt) && (w == 1) && (bp->count >= wcnt) && (!is_ignored_IP(bp->recvfrom, SRC_ALL, cdbhash(bp->recvfrom, sizeof(bp->recvfrom))))) {
                        	printf("Light Spammer: %s - %s  sent %d mails\n", bp->mail, bp->recvfrom, bp->count);
				snprintf(mailbuf, sizeof(mailbuf) - 1, "%s - %s has been spamming your box! (sent %d mails)\n This mail is to notify you that this email address sent more emails than\n your \"warning threshold\", I'm not adding it to %s\n\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", bp->mail, bp->recvfrom, bp->count, badmailfile, VERSION);
				mailbuf[sizeof(mailbuf) - 1] = '\0';
				send_notify_mail(mailbuf, bp->recvfrom, "warning ");
		    	}
			
			if (bp->count >= bcnt) {
				if (p == 1 && (bp->count >= pcnt) && (!is_ignored_IP(bp->recvfrom, SRC_BADMAILFROM, cdbhash(bp->recvfrom, sizeof(bp->recvfrom)))) && (!is_ignored_IP(bp->recvfrom, SRC_IGNOREFILE, cdbhash(bp->recvfrom, sizeof(bp->recvfrom))))) {
					spamcnt = 1;
                            		fprintf(fp, "%s\n", bp->recvfrom);
					bp->is_spammer = 1;
					printf("Paranoid Spammer: %s - %s  sent %d mails\n", bp->mail, bp->recvfrom, bp->count);
					snprintf(mailbuf, sizeof(mailbuf - 1), " %s - %s has been spamming your box! (sent %d mails)\n No matter this mail address is matched against your spam high list: %s, or not. I'm still adding it to blacklist since s/he sent more mails then your paranoid threshold.\n\n Source mail address has been added to %s file\n Target successfully nuked!\n\n Regards,\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", bp->mail, bp->recvfrom, bp->count, highfile, badmailfile, VERSION);
					mailbuf[sizeof(mailbuf - 2)] = '\0';  /* -1 is for NULL byte, the other -1 is for 'Sir BALABAN Byte' ... */
					send_notify_mail(mailbuf,  bp->recvfrom, "paranoid ");
                         	}
		
                         	else if (!is_ignored_IP(bp->recvfrom, SRC_ALL, cdbhash(bp->recvfrom, sizeof(bp->recvfrom)))) {
			 		spamcnt = 1;
					fprintf(fp, "%s\n", bp->recvfrom);
                                        bp->is_spammer = 1;
					printf("Spammer: %s - %s  sent %d mails\n", bp->mail, bp->recvfrom, bp->count);
				        snprintf(mailbuf, sizeof(mailbuf) - 1, " %s - %s has been spamming your box! (sent %d mails)\n Source mail address has been added to %s file\n Target successfully nuked!\n\n Regards,\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", bp->mail, bp->recvfrom, bp->count, badmailfile, VERSION);
			                mailbuf[sizeof(mailbuf) - 1] = '\0';
				        send_notify_mail(mailbuf,  bp->recvfrom, "blocked ");
                        	}
	                }
		}
        
        if (fclose(fp) != 0) {
        	fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
        }

	if (enable_subj_filt)
		update_qsheff_rules();

	free_hash_tables();

        return spamcnt;
}
