#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include "loadconfig.h"

extern int errno;
extern int w;
extern int b;
extern int p;

void
loadconfig(const char *cfgfile)
{
	FILE *fd = NULL;
	char buf[BUFSIZE];
	char keyword[KEYSIZE];
	char value[VALSIZE];
	char *cp1, *cp2;
	char *variables[] = {
		"Invalid",
		"logtype",
		"logfile",
		"ignorefile",
		"badmailfile",
		"hostname",
		"sysadmin",
		"statfile",
		"mail_command",
		"makemap_command",
		"wcnt",
		"bcnt",
		"pcnt",
		"highfile",
		"enable_subj_filt",
		"qsheff_rules_file",
		"trim_subj_str"
	};

	int i = 0, j = 0, key = 0, line = 0, lenbuf = 0, keyword_nums = sizeof(variables)/sizeof(char *);

	if ((fd = fopen(cfgfile, "r")) == NULL) {
		fprintf(stderr, "loadconfig: cannot open spamguard configuration file %s, exiting...\n", cfgfile);
		exit(-1);
	}
	
	while ((fgets(buf, BUFSIZE, fd)) != NULL) {
		line++;
		if (buf[0] == '#') 
			continue;
		if ((lenbuf = strlen(buf)) <= 1)
			continue;
		cp1 = buf;
		cp2 = keyword;
		while (isspace((int)*cp1) && ((cp1 - buf) < lenbuf)) 
			cp1++;
		while (isgraph((int)*cp1) && (*cp1 != '=') && (j++ < KEYSIZE - 1) && ((cp1 - buf) < lenbuf)) 
			*cp2++ = *cp1++;
		*cp2 = '\0';
		j = 0;
		cp2 = value;
		while ((*cp1 != '\0') && (*cp1 !='\n') && (*cp1 !='=') && ((cp1 - buf) < lenbuf))
			cp1++;
		cp1++; 
		while (isspace((int)*cp1) && ((cp1 - buf) < lenbuf))
			cp1++; 
		if (*cp1 == '"') 
			cp1++;
		while ((*cp1 != '\0') && (*cp1 !='\n') && (*cp1 !='"') && (j++ < VALSIZE - 1) && ((cp1 - buf) < lenbuf))
			*cp2++ = *cp1++;
		*cp2-- = '\0';
		j = 0;
		if (keyword[0] =='\0' || value[0] =='\0')
			continue;
		key = 0;
		for (i = 0; i < keyword_nums; i++) {
			if ((strncmp(keyword, variables[i], KEYSIZE)) == 0) {
				key = i;
				break;
			}
		}

		switch(key) {
			case 0:
				fprintf(stderr, "Illegal Keyword: %s\n", keyword);
				break;
			case 1:
				strncpy(logtype, value, VALSIZE);
				break;
			case 2:
				strncpy(logfile, value, VALSIZE);
				break;
			case 3:
				strncpy(ignorefile, value, VALSIZE);
				break;
			case 4:
				strncpy(badmailfile, value, VALSIZE);
				break;
			case 5:
				strncpy(hostname, value, VALSIZE);
				break;
			case 6:
				strncpy(sysadmin, value, VALSIZE);
				break;
			case 7:
				strncpy(statfile, value, VALSIZE);
				break;
			case 8:
				strncpy(mail_command, value, VALSIZE);
				break;
			case 9:
				strncpy(makemap_command, value, VALSIZE);
				break;
			case 10:
				wcnt = atoi(value);
				w = 1;
				break;
			case 11:
				bcnt = atoi(value);
				b = 1;
				break;
			case 12:
				pcnt = atoi(value);
				p = 1;
				break;
			case 13:
				pcnt = atoi(value);
				strncpy(highfile, value, VALSIZE);
				break;
                        case 14:
                                enable_subj_filt = atoi(value);
                                break;
                        case 15:
                                strncpy(qsheff_rules_file, value, VALSIZE);
                                break;
                        case 16:
                                strncpy(trim_subj_str, value, VALSIZE);
                                break;
		}
	}

	if (fclose(fd) != 0) {
		fprintf(stderr, "File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));
		exit(-1);
	}
}

void
readconfig(const char *cfgfile)
{
	struct stat statbuf;

	loadconfig(cfgfile);

	printf("logtype: %s\n", logtype);
	printf("logfile: %s\n", logfile);
	printf("ignorefile: %s\n", ignorefile);
	printf("highfile: %s\n", highfile);
	printf("badmailfile: %s\n", badmailfile);
	printf("statfile: %s\n", statfile);
	printf("warning count: %d\n", wcnt);
	printf("block count: %d\n", bcnt);
	printf("paranoid count: %d\n", pcnt);
        printf("qsheff subject filtering: %d\n", enable_subj_filt);
	printf("qsheff rules file: %s\n", qsheff_rules_file);
        printf("trim subject string: %s\n", trim_subj_str);

	if ((enable_subj_filt != 0) && (enable_subj_filt != 1) && (enable_subj_filt) != 2) {
                printf("enable_subj_filt value must be 0, 1 or 2\n");
                exit(-1);
        }

	if (b == 0) {
		printf("You must set block count(bcnt) value in spamguard.conf\n");
		exit(-1);
	}

	if (w && b && (wcnt >= bcnt)) {
		printf("Error!: warning count value:%d must be smaller than block count value:%d\n", wcnt, bcnt);
		exit(-1);
	}
	
	if (w && (wcnt >= pcnt)) {
		printf("Error!: warning count value:%d must be smaller than paranoid count value:%d\n", wcnt, pcnt);
		exit(-1);
	}
	
	if (b && (bcnt >= pcnt)) {
		printf("Error!: block count value:%d must be smaller than paranoid count value:%d\n", bcnt, pcnt);
		exit(-1);
	}

	if ((strlen(hostname)) <= 0 )
        	gethostname(hostname, VALSIZE);
	        printf("hostname: %s\n", hostname);

	if ((strcasecmp(logtype, "qmail") != 0) && (strcasecmp(logtype, "sendmail") != 0)
		&& (strcasecmp(logtype, "postfix") != 0)
		&& (strcasecmp(logtype, "qsheff") != 0) && (strcasecmp(logtype, "exim") != 0)) {
		printf("Invalid logtype: %s\naccepted logytpes are: "
		        "qmail, qsheff, exim, sendmail or postfix\n", logtype);
                exit(-1);
	}
	
	if ((stat(logfile, &statbuf)) == 0) {
		if((S_ISREG(statbuf.st_mode)) == 0) {
			fprintf(stderr, "You are using: %s log type "
					"logfile: %s  must be a regular file\n", logtype, logfile);
			exit(-1);
		}
	}
	
	else {
		fprintf(stderr, "You are using: %s log type "
				"logfile: %s file does not exist!\n", logtype, logfile);
		exit(-1);
	}

	if ((strlen(ignorefile)) <= 0) {
		printf("You must define a ignorefile\n");
		exit(-1);
	}
	
	if ((strlen(badmailfile)) <= 0) {
		printf("You must define a badmailfile\n");
		exit(-1);
	}
	
	if ((strlen(sysadmin)) <= 0) {
		printf("You must define a sysadmin email address\n");
		exit(-1);
	}

	if ((strlen(mail_command)) <= 0) {
		printf("You must set mail_command value\n");
		exit(-1);
	}
	
	if (((strcasecmp(logtype, "sendmail") == 0) || (strcasecmp(logtype, "postfix") == 0)) && (strlen(makemap_command) == 0)){
		printf("You are using logtype:%s, you must set makemap_command value\n", logtype);
		exit(-1);
	}

        if ((strlen(qsheff_rules_file)) <= 0) {
                printf("Wonna enabling qsheff subject filtering? Please specify a valid path for qsheff rules file\n");
                exit(-1);
	}

        if ((strlen(trim_subj_str) <= 0) && (enable_subj_filt == 2)) {
                printf("Wonna trimming subjects? Please type valid word(s) or change 'enable_subj_filt' value to 0 or 1\n");
                exit(-1);
        }
}
