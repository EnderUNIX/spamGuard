#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#define	SRC_IGNOREFILE	0x02
#define	SRC_BADMAILFROM	0x04
#define	SRC_HIGHFILE	0x08
#define	SRC_ALL		0xFF

#define MAXADDR         5381

typedef struct maddr maddr;
typedef struct iaddr iaddr;

typedef struct hist_stat {
        int inode;
        int saved_pos;
} hist_stat;

struct maddr {
        char *mail;
        int cnt;
        maddr *next;
};

struct iaddr {
	char *mail;
	char src;
	iaddr *next;
};

maddr *spammer_hash[MAXADDR];
iaddr *iaddrlist;

int
is_ignored(char *, char);

void
check_addr(char *);

void
add_ignored(char *, char);

int
removespaces(char *, int);

int
send_notify_mail(char *, char *, char *);

void
save_pos(hist_stat *);

void
get_saved_pos(hist_stat *);

int
makemap(void);

void
load_ignore_list(char *, char);

void
load_ignore_sendmail(char *, char);

int
qmail_finalize(void);

int
sendmail_finalize(void);

int
exim_finalize(void);

void
print_list(int);


#endif
