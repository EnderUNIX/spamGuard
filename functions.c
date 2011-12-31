#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include "loadconfig.h"
#include "functions.h"
#include "wildmat.h"
#include "hash.h"

extern char mail_command[VALSIZE];
extern char makemap_command[VALSIZE];
extern char sysadmin[VALSIZE];
extern char statfile[VALSIZE];
extern char badmailfile[VALSIZE];

extern int wcnt;
extern int bcnt;
extern int pcnt;

extern int w;
extern int b;
extern int p;

int
is_ignored(char *email, char src)
{
	iaddr *l = iaddrlist;

	for ( ; l !=  NULL; l = l->next) {
		if (src & l->src)
			if (DoMatch(email, l->mail, strlen(l->mail)) == TRUE) 
				return 1;
	}
	return 0;
}

void
check_addr(char *email)
{
	int h = 0;
	maddr *sym = NULL;

	if(strncmp(email, "#@[]", 4) == 0)
		return;

	h = cdbhash(email, sizeof(email));
	for (sym = spammer_hash[h]; sym != NULL; sym = sym->next)
		if (strcmp(email, sym->mail) == 0) {
			sym->cnt++;
			return;
		}
	sym = (maddr *)malloc(sizeof(maddr));
	sym->mail = email;
	sym->cnt = 1;
	sym->next = spammer_hash[h];
	spammer_hash[h] = sym;
	return;
}

void
add_ignored(char *email, char src) 
{

	iaddr *new = NULL;

	new = (iaddr *)malloc(sizeof(iaddr));
	new->mail = email;
	new->src = src;
	new->next = iaddrlist;
	iaddrlist = new;
}

int
removespaces(char *buf, int len)
{
	char *cp = buf;
	char *sv = buf;

	for (; *buf != '\0' && ((buf - sv) < len); buf++)
		if (*buf == ' ' || *buf == '<' || *buf == '>' || *buf == '\n' || *buf == '\r' || *buf == '\t')
			continue;
		else
			*cp++ = *buf;
	*cp = '\0';
	return cp - sv;
}


int
send_notify_mail(char *n, char *sender, char *spam_type)
{

        FILE *inpp = NULL;
        char tmpfile[BUFSIZE];
        char mailcmd[BUFSIZE];
        int fd = 0, retval = 0, ret = 0;
        size_t bytes = 0;

        strncpy(tmpfile, "/tmp/qstspam-XXXXXX", BUFSIZE - 1);
        if ((fd = mkstemp(tmpfile)) == -1) {
                puts("Couldn't create temporary file name");
                perror("mkstemp");
         	return errno;
        }

        if ((bytes = write(fd, n, strlen(n))) < bytes) {
                fprintf(stderr, "Couldn't write to temporary file");
                return errno;
        }

        if ((ret = close(fd)) == -1) {
                fprintf(stderr, "Couldn't close temporary file");
                perror("close");
                return errno;
        }

        strncpy(mailcmd, mail_command, BUFSIZE - 1);
        strncat(mailcmd, " -s  \"spamGuard notification  ", BUFSIZE - 1);
        strncat(mailcmd, spam_type, BUFSIZE - 1);
        strncat(mailcmd, sender, BUFSIZE - 1);
        strncat(mailcmd, " \"  ", BUFSIZE - 1);
        strncat(mailcmd, sysadmin, BUFSIZE - 1);
        strncat(mailcmd, " < ", BUFSIZE - 1);
        strncat(mailcmd, tmpfile, BUFSIZE - 1);

        if ((inpp = popen(mailcmd, "r")) == NULL) {
                fprintf(stderr, "Couldn't send mail");
                perror("popen");
                return errno;
        }

	if ((retval = pclose(inpp)) == -1) {
		perror("pclose");
		return errno;
        }

        if ((ret = unlink(tmpfile)) == -1) {
                perror("unlink");
                return errno;
        }

        return retval;
}

void
save_pos(hist_stat *h)
{
	FILE *fp = NULL;

	if (h == NULL)
		return;

	if ((fp = fopen(statfile, "w")) == NULL) {
		fprintf(stderr, "Couldn't open %s: %s\n", statfile, strerror(errno));
		return;
	}

	fprintf(fp, "%d %d", h->inode, h->saved_pos);
	if ((fclose(fp)) == -1) {
		fprintf(stderr, "Couldn't close %s: %s\n", statfile, strerror(errno));
		return;
	}
}

void
get_saved_pos(hist_stat *h)
{
	FILE *fp = NULL;
	char inode[16];
	char pos[16];

	if (h == NULL)
		return;

	if ((fp = fopen(statfile, "r")) == NULL) {
		fprintf(stderr, "Couldn't open %s: %s\n", statfile, strerror(errno));
		return;
	}

	fscanf(fp, "%15s %15s", inode, pos);

	if (inode != NULL)
		h->inode = atoi(inode);

	if (pos != NULL)
		h->saved_pos = atoi(pos);

	if ((fclose(fp)) == -1) {
		fprintf(stderr, "Couldn't close %s: %s\n", statfile, strerror(errno));
		return;
	}
}

int
makemap(void)
{
	FILE *fp = NULL;
	int retval = 0;

	if ((fp = popen(makemap_command, "r")) == NULL) {
		fprintf(stderr, "Couldn't create hash database file\n");
		perror("popen");
	}

	if ((retval = pclose(fp)) == -1) {
		perror("pclose");
		return errno;
	}

	return retval;
}

void
load_ignore_list(char *fn, char src) 
{

	FILE *fp = NULL;
	char buf[1024];

	if ((fp = fopen(fn, "r")) == NULL) {
		fprintf(stderr, "fopen: %s: %s\n", fn, strerror(errno));
		exit(-1);
	}

	memset(buf, 0x0, sizeof(buf));
	while ((fgets(buf, 1024, fp)) != NULL) {
		removespaces(buf, strlen(buf));
		add_ignored(strdup(buf), src);
		memset(buf, 0x0, sizeof(buf));
	}

	if (fclose(fp) != 0) {
		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
	}
}

void
load_ignore_sendmail(char *fn, char src) 
{

	FILE *fp = NULL;
	char buf[1024];
	char *m = NULL;

	if ((fp = fopen(fn, "r")) == NULL) {
		fprintf(stderr, "fopen: %s: %s\n", fn, strerror(errno));
		exit(-1);
	}

	memset(buf, 0, sizeof(buf));
	while ((fgets(buf, 1024, fp)) != NULL) {
		if (buf[0] == '#' || buf[0] == ' ')
			continue;
		m = strtok(buf, "\t");
		if (m == NULL)
			continue;
		removespaces(m, strlen(m));
		add_ignored(strdup(m), src);
		memset(buf, 0, sizeof(buf));
	}

	if (fclose(fp) != 0){
		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
	}
}

int
qmail_finalize(void)
{

	FILE *fp = NULL;
	maddr *ptr = NULL;
	char mailbuf[2048];
	int i = 0, spamcnt = 0;

	if ((fp = fopen(badmailfile, "a+")) == NULL) {
		fprintf(stderr, "fopen: %s: %s\n", badmailfile, strerror(errno));
		exit(-1);
	}

	for (i = 0; i < MAXADDR; i++) 
		for (ptr = spammer_hash[i];  ptr != NULL; ptr = ptr->next) {
			if ((ptr->cnt < bcnt) && w == 1 && (ptr->cnt >= wcnt) && (!is_ignored(ptr->mail, SRC_ALL))) {
				printf("Light Spammer:%s  sent %d mails\n", ptr->mail, ptr->cnt);
				snprintf(mailbuf, 2047, " %s has been spamming your box! (sent %d mails)\n This mail is to notify you that this email address sent more emails than\n your \"warning threshold\", I'm not adding it to %s\n\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", ptr->mail, ptr->cnt, badmailfile, VERSION);
				mailbuf[sizeof(mailbuf) - 1] = '\0';
				send_notify_mail(mailbuf, ptr->mail, "warning ");
			}
			
			else if (ptr->cnt >= bcnt) {
				if (p == 1 && (ptr->cnt >= pcnt) && (!is_ignored(ptr->mail, SRC_BADMAILFROM))  
					   && (!is_ignored(ptr->mail, SRC_IGNOREFILE))) {
					spamcnt = 1;
					fprintf(fp, "%s\n", ptr->mail);
					printf("Paranoid Spammer:%s  sent %d mails\n", ptr->mail, ptr->cnt);
					snprintf(mailbuf, 2047, " %s has been spamming your box! (sent %d mails)\n No matter this mail address is matched against your spam high list: %s, or not. I'm still adding it to blacklist since s/he sent more mails then your paranoid threshold.\n\n Source mail address has been added to %s file\n Target successfully nuked!\n\n Regards,\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", ptr->mail, ptr->cnt, highfile, badmailfile, VERSION);
					mailbuf[sizeof(mailbuf) - 1] = '\0';
					send_notify_mail(mailbuf,  ptr->mail, "paronaid ");
				}
				else if (!is_ignored(ptr->mail, SRC_ALL)) {
					spamcnt = 1;
					fprintf(fp, "%s\n", ptr->mail);
					printf("Spammer:%s  sent %d mails\n", ptr->mail, ptr->cnt);
					snprintf(mailbuf, 2047, " %s has been spamming your box! (sent %d mails)\n Source mail address has been added to %s file\n Target successfully nuked!\n\n Regards,\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", ptr->mail, ptr->cnt, badmailfile, VERSION);
					mailbuf[sizeof(mailbuf) - 1] = '\0';
					send_notify_mail(mailbuf,  ptr->mail, "blocked ");
				}
			}
		}
	if (fclose(fp) != 0) {
		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
	}

	return spamcnt;
}

int
sendmail_finalize(void)
{

	FILE *fp = NULL;
	maddr *ptr = NULL;
	char mailbuf[2048];
	int i = 0, spamcnt = 0;
	
	if ((fp = fopen(badmailfile, "a+")) == NULL) {
		fprintf(stderr, "fopen: %s: %s\n", badmailfile, strerror(errno));
		exit(-1);
	}

	for (i = 0; i < MAXADDR; i++) 
		for (ptr = spammer_hash[i];  ptr != NULL; ptr = ptr->next) {
			if ((ptr->cnt < bcnt) && w && (ptr->cnt >= wcnt) &&  (!is_ignored(ptr->mail, SRC_ALL))) {
				printf("Light Spammer:%s  sent %d mails\n", ptr->mail, ptr->cnt);
				snprintf(mailbuf, 2047, " %s has been spamming your box! (sent %d mails)\n This mail is to notify you that this email address sent more emails than\n your \"warning threshold\", I'm not adding it to %s\n\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", ptr->mail, ptr->cnt, badmailfile, VERSION);
				mailbuf[sizeof(mailbuf) - 1] = '\0';
				send_notify_mail(mailbuf, ptr->mail, "warning ");
			}
	
			else if (ptr->cnt >= bcnt) {
				if (p == 1 && (ptr->cnt >= pcnt) && (!is_ignored(ptr->mail, SRC_BADMAILFROM))
			 		   && (!is_ignored(ptr->mail, SRC_IGNOREFILE)))	{
					spamcnt = 1;
					fprintf(fp, "%s\tERROR:\"550: Your address is blocked because of spammer activity [http://www.enderunix.org/spamguard]\"\n", ptr->mail);
					printf("Paranoid Spammer:%s  sent %d mails\n", ptr->mail, ptr->cnt);
					snprintf(mailbuf, 2047, " %s has been spamming your box! (sent %d mails)\n No matter this mail address is matched against your high list:%s, or not. I'm still adding it to blacklist since s/he sent more mails then your paranoid threshold.\n\n Source mail address has been added to %s file\n Target successfully nuked!\n\n Regards,\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", ptr->mail, ptr->cnt, highfile, badmailfile, VERSION);
					mailbuf[sizeof(mailbuf) - 1] = '\0';
					send_notify_mail(mailbuf,  ptr->mail, "paranoid ");
				}
				else if (!is_ignored(ptr->mail, SRC_ALL)) {
					spamcnt = 1;
					fprintf(fp, "%s\tERROR:\"550: Your address is blocked because of spammer activity [http://www.enderunix.org/spamguard]\"\n", ptr->mail);
					printf("Spammer:%s  sent %d mails\n", ptr->mail, ptr->cnt);
					snprintf(mailbuf, 2047, " %s has been spamming your box! (sent %d mails)\n Source mail address has been added to %s file\n Target successfully nuked!\n\n Regards,\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", ptr->mail, ptr->cnt, badmailfile, VERSION);
					mailbuf[sizeof(mailbuf) - 1] = '\0';
					send_notify_mail(mailbuf,  ptr->mail, "blocked ");
				}
			}
		}
	if (fclose(fp) != 0) {
		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
	}

	return spamcnt;
}

int
exim_finalize(void)
{

	FILE *fp = NULL;
	maddr *ptr = NULL;
	char mailbuf[2048];
	int i = 0, spamcnt = 0;
	
	if ((fp = fopen(badmailfile, "a+")) == NULL) {
		fprintf(stderr, "fopen: %s: %s\n", badmailfile, strerror(errno));
		exit(-1);
	}

	for (i = 0; i < NUM_HASH; i++) 
		for (ptr = spammer_hash[i];  ptr != NULL; ptr = ptr->next) {
			if ((ptr->cnt < bcnt) && w && (ptr->cnt >= wcnt) &&  (!is_ignored(ptr->mail, SRC_ALL))) {
				printf("Light Spammer:%s  sent %d mails\n", ptr->mail, ptr->cnt);
				snprintf(mailbuf, 2047, " %s has been spamming your box! (sent %d mails)\n This mail is to notify you that this email address sent more emails than\n your \"warning threshold\", I'm not adding it to %s\n\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", ptr->mail, ptr->cnt, badmailfile, VERSION);
				mailbuf[sizeof(mailbuf) - 1] = '\0';
				send_notify_mail(mailbuf, ptr->mail, "warning ");
			}
	
			else if (ptr->cnt >= bcnt) {
				if (p == 1 && (ptr->cnt >= pcnt) && (!is_ignored(ptr->mail, SRC_BADMAILFROM))
			 		   && (!is_ignored(ptr->mail, SRC_IGNOREFILE)))	{
					spamcnt = 1;
					fprintf(fp, "%s\n", ptr->mail);
					printf("Paranoid Spammer:%s  sent %d mails\n", ptr->mail, ptr->cnt);
					snprintf(mailbuf, 2047, " %s has been spamming your box! (sent %d mails)\n No matter this mail address is matched against your high list:%s, or not. I'm still adding it to blacklist since s/he sent more mails then your paranoid threshold.\n\n Source mail address has been added to %s file\n Target successfully nuked!\n\n Regards,\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", ptr->mail, ptr->cnt, highfile, badmailfile, VERSION);
					mailbuf[sizeof(mailbuf) - 1] = '\0';
					send_notify_mail(mailbuf,  ptr->mail, "paranoid ");
				}
				else if (!is_ignored(ptr->mail, SRC_ALL)) {
					spamcnt = 1;
					fprintf(fp, "%s\n", ptr->mail);
					printf("Spammer:%s  sent %d mails\n", ptr->mail, ptr->cnt);
					snprintf(mailbuf, 2047, " %s has been spamming your box! (sent %d mails)\n Source mail address has been added to %s file\n Target successfully nuked!\n\n Regards,\n -EnderUNIX spamGuard %s\n http://www.enderunix.org/spamguard\n", ptr->mail, ptr->cnt, badmailfile, VERSION);
					mailbuf[sizeof(mailbuf) - 1] = '\0';
					send_notify_mail(mailbuf,  ptr->mail, "blocked ");
				}
			}
		}
	if (fclose(fp) != 0) {
		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
	}

	return spamcnt;
}


void
print_list(int list)
{
	int i = 0;
	maddr *m = NULL;
	list = 0;
	
	for (i = 0; i < MAXADDR; i++) 
		if (spammer_hash[i] != NULL) 
			for (m = spammer_hash[i]; m != NULL; m = m->next)
				printf("%s - %d mails\n", m->mail, m->cnt);
}

