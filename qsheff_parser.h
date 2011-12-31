#ifndef __QSHEFFPARSER__
#define __QSHEFFPARSER__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "hash.h"
#include "wildmat.h"
#include "functions.h"
#include "loadconfig.h"

#define MAXLINE        1024
#define MAX_TRIM_WORDS 10

extern void 
parse_qsheff_log(const char* logfile);

extern void
load_ignored_IP(const char* IP_file, char src);

extern int
is_ignored_IP(char* IP, char src, unsigned int h);

extern int
qsheff_finalize(void);


#endif
