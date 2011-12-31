/*
 *
 * EnderUNIX Software Development Team @ Turkey
 * (c) 200 Istanbul, Turkiye
 * 
 * See COPYING for copyright and copying restrictions
 *
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "wildmat.h"
#include "parser.h"
#include "loadconfig.h"
#include "functions.h"
#include "hash.h"
#include "qsheff_parser.h"
#include "config.h"

extern char logtype[VALSIZE];
extern char logfile[VALSIZE];
extern char ignorefile[VALSIZE];
extern char badmailfile[VALSIZE];

int w = 0;
int b = 0;
int p = 0;

int
main(int argc, char **argv)
{
        int c = 0, f = 0, error = 0;
	extern char *optarg;
        extern int optind;
        char spamguardconf[VALSIZE];

        while (!error && (c = getopt(argc, argv, "f:hv")) != -1) {
                switch (c) {
	                case 'v':
        	                printf("EnderUNIX spamGuard Version %s\n", VERSION);
                	        exit(0);
                        	break;
	                case 'h':
        	                printf("Usage: %s [-f spamguard.conf]\n", argv[0]);
                	        exit(0);
                        	break;
	                case 'f':
        	                strncpy(spamguardconf, optarg, VALSIZE - 1);
                		f = 1;
	                        break;
        	        default:
                	        error = 1;
                        	puts("Usage: spamGuard [-f spamguard.conf]");
	                        exit(-1);
        	                break;
                }
        }

        if (f == 0)
                 readconfig(CONFIGFILE);
        else
                 readconfig(spamguardconf);
        
	iaddrlist = NULL;
        
        if (strcmp(logtype, "qmail") == 0) {
                read_logfile(logfile);
                load_ignore_list(ignorefile,  SRC_IGNOREFILE);
                load_ignore_list(ignorefile,  SRC_HIGHFILE);
                load_ignore_list(badmailfile, SRC_BADMAILFROM);
                
		printf("Spammers:\n");
                if (qmail_finalize() > 0)
                        printf("Spammer is detected\n");
                else
                        printf("No spammer found yet\n");
        }

	if ((strcmp(logtype, "sendmail") == 0) ||  (strcmp(logtype, "postfix") == 0)) {
                read_logfile(logfile);
                load_ignore_list(ignorefile, SRC_IGNOREFILE);
                load_ignore_list(ignorefile, SRC_HIGHFILE);
                load_ignore_sendmail(badmailfile, SRC_BADMAILFROM);
                
		printf("Spammers:\n");
                if (sendmail_finalize() > 0)
                        printf("Spammer is detected\n");
                else
                        printf("No spammer found yet\n");
	}

        if (strcmp(logtype, "qsheff") == 0) {
		parse_qsheff_log(logfile);	
		load_ignored_IP(ignorefile,  SRC_IGNOREFILE);
		load_ignored_IP(ignorefile,  SRC_HIGHFILE);
		load_ignored_IP(badmailfile, SRC_BADMAILFROM);
		
		printf("Spammers:\n");
                if (qsheff_finalize() > 0)
                        printf("Spammer is detected\n");
                else
                        printf("No spammer found yet\n");
	}
	
	if ((strcmp(logtype, "exim") == 0)) {
                read_logfile(logfile);
                load_ignore_list(ignorefile, SRC_IGNOREFILE);
                load_ignore_list(ignorefile, SRC_HIGHFILE);
                load_ignore_list(badmailfile, SRC_BADMAILFROM);

                printf("Spammers:\n");
                if (exim_finalize() > 0)
                        printf("Spammer is detected\n");
                else
                        printf("No spammer found yet\n");
        }
	
	return 0;
}
