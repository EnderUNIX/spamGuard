#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>

void
read_logfile(char *);

void
qmail_parseline(char *);

void
sendmail_parseline(char *str);

void
exim_parseline(char *);

#endif
