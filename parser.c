#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "wildmat.h"
#include "functions.h"
#include "loadconfig.h"
#include "parser.h"

extern char logtype[VALSIZE];

void
read_logfile(char *fn) 
{	
	FILE *fp = NULL;
	char buf[1024];
	struct stat st;
	hist_stat old;
	hist_stat new;

	get_saved_pos(&old);

	if ((fp = fopen(fn, "r")) == NULL) {
		fprintf(stderr, "fopen: %s: %s\n", fn, strerror(errno));
		exit(-1);
	}
        
	if ((stat(fn, &st)) == -1) {
                fprintf(stderr, "Couldnt' stat %s: %s\n", fn, strerror(errno));
                exit(-1);
        }
        /* If both inode numbers are the same, we assume that log file
	 *          * has not been changed (i.e rotated, removed), so we can
	 *                   * go past offset bytes and continue to read new logs */
        if (st.st_ino == old.inode)
                fseek(fp, old.saved_pos, SEEK_SET);

	if (strcmp(logtype, "qmail") == 0) {
		while ((fgets(buf, 1024, fp)) != NULL) 
			qmail_parseline(buf);
	}

	else if ((strcmp(logtype, "sendmail") == 0) ||  (strcmp(logtype, "postfix") == 0)) {
		while ((fgets(buf, 1024, fp)) != NULL) 
			sendmail_parseline(buf);
	}

	else if (strcmp(logtype, "exim") == 0) {
                while ((fgets(buf, 1024, fp)) != NULL)
                        exim_parseline(buf);
        }

        new.inode = st.st_ino;
        new.saved_pos = ftell(fp);
        save_pos(&new);
	if (fclose(fp) != 0) {
		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
	}
}

void
qmail_parseline(char *str)
{
	char *p = str;
	char email[300];
	char domain[128];
	char user[128];
	int i = 0;
	int lenstr  = strlen(str);

	if ((p = strstr(str, "from ")) == NULL)
		return ;

	if ((p - str) > lenstr)
		return;

	p += 6;
	for (i = 0; (*p != '@') && (*p != '\0') && (*p != '\r') && (*p != '\n') && (i < 127) && ((p - str) < lenstr); i++, p++)
		user[i] = *p;
	user[i] = '\0';

	if (strlen(user) == 0)
		return;

	p++;
	for (i = 0; (*p != '>') && (*p != '\0') && (*p != '\r') && (*p != '\n') && (i < 127) && ((p - str) < lenstr); i++, p++)
		domain[i] = *p;
	domain[i] = '\0';
	if (strlen(domain) == 0)
		return;
	sprintf(email, "%.128s@%.128s", user, domain);
	check_addr(strdup(email));
}

void
sendmail_parseline(char *str)
{
	char *p = str;
	char domain[128];
	char user[128];
	char email[300];
	int i = 0;
	int lenstr = strlen(str);
	int domainflg = 0;

	if ((p = strstr(str, "from=")) == NULL)
		return ;
	
	if ((p - str) > lenstr)
		return;

	p += 5;
	if (*p == '<')
		p++;
	for (i = 0; (*p != ',') && (*p != '>') && (*p != '\0') && (*p != '\r') && (*p != '\n') && (i < 127) && ((p - str) < lenstr); i++, p++) {
			if (*p == '@') {
				domainflg = 1;
				break;
			}
			user[i] = *p;
	}
	user[i] = '\0';
	if (strlen(user) == 0)
		return;

	if (domainflg) {
		p++;
		for (i = 0; (*p != ',') && (*p != '>') && (*p != '\0') && (*p != '\r') && (*p != '\n') && (i < 127) && ((p - str) < lenstr); i++, p++)
			domain[i] = *p;
		domain[i] = '\0';
		if (strlen(domain) == 0)
			return;
	} else
			strncpy(domain, hostname, 127);

	sprintf(email, "%.128s@%.128s", user, domain);
	check_addr(strdup(email));
}

void
exim_parseline(char *str)
{
	char *p = str;
	char email[300];
	char domain[128];
	char user[128];
	int i = 0;
	int lenstr  = strlen(str);

	if ((p = strstr(str, "<= ")) == NULL)
		return ;

	if ((p - str) > lenstr)
		return;

	p += 3;
	for (i = 0; (*p != '@') && (*p != '<') && (*p != '\0') && (*p != '\r') && (*p != '\n') && (i < 127) && ((p - str) < lenstr); i++, p++)
		user[i] = *p;
	user[i] = '\0';

	if (strlen(user) == 0)
		return;

	p++;
	for (i = 0; (*p != ' ') && (*p != '\0') && (*p != '\r') && (*p != '\n') && (i < 127) && ((p - str) < lenstr); i++, p++)
		domain[i] = *p;
	domain[i] = '\0';
	if (strlen(domain) == 0)
		return;
	sprintf(email, "%.128s@%.128s", user, domain);
	check_addr(strdup(email));

}
