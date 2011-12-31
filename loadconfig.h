#ifndef LOADCONFIG_H
#define LOADCONFIG_H

#include <stdio.h>

#define TOKENS " \n"
#define VERSION "1.9"

enum {
        BUFSIZE = 1024, 
        KEYSIZE = 64,
        VALSIZE = 256
};

int wcnt;
int bcnt;
int pcnt;
int enable_subj_filt;

char logtype[VALSIZE];
char logfile[VALSIZE];
char ignorefile[VALSIZE];
char highfile[VALSIZE];
char badmailfile[VALSIZE];
char hostname[VALSIZE];
char sysadmin[VALSIZE];
char statfile[VALSIZE];
char mail_command[VALSIZE];
char makemap_command[VALSIZE];
char qsheff_rules_file[VALSIZE];
char trim_subj_str[VALSIZE];

void
loadconfig(const char *);

void
readconfig(const char *);


#endif
