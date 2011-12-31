#EnderUNIX spamguard Makefile.am file
SUBDIRS = tr
bin_PROGRAMS = spamguard
spamguard_SOURCES = functions.c loadconfig.c main.c parser.c wildmat.c qsheff_parser.c hash.c
spamguard_LDADD 	=

spamguard_docdir = ${prefix}/share/doc/spamguard
spamguard_doc_DATA = AUTHORS\
	CHANGELOG\
	COPYING\
	INSTALL\
	README\
	README.DigitalUnix\
	POST-INSTALL\
	THANKS\
	TODO\
	UPGRADE
	

spamguard_confdir = ${sysconfdir}/spamguard
spamguard_conf_DATA = spam-ignore.txt\
	spam-ignore.txt.sample\
	spam-high.txt\
	spamguard.conf\
	spamguard.conf.sample\
	spamguard_qsheff.conf\
	spamguard_qsheff.conf.sample\
	qsheff_ignore\
	qsheff_ignore.sample\
	qsheff_high

spamguard_headers = functions.h\
	loadconfig.h\
	parser.h\
	wildmat.h\
	qsheff_parser.h\
	hash.h

EXTRA_DIST = ${spamguard_doc_DATA} ${spamguard_conf_DATA} ${spamguard_headers}


#This is not a gnu project. So we don't have to obey gnu package needz!
AUTOMAKE_OPTIONS = foreign

# set the include path found by configure
INCLUDES= $(all_includes)

# the library search path.
spamguard_LDFLAGS = $(all_libraries)

