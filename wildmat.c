#include "wildmat.h"

/* Taken from spamcontrol patch. 
 *
 * Author:
 *         Dr. Erwin Hoffmann - FEHCom Germany
 *         E-Mail: feh@fehcom.de
 *
 */

int
DoMatch(char *text, char *p, int plen)
{
    register int	last;
    register int	matched;
    register int	reverse;
    register char * savep = p;
    register char * savet = text;

    for ( ; *p && (p - savep) < plen; text++, p++) {
	if (*text == '\0' && *p != '*')
	    return ABORT;
	switch (*p) {
	case '\\':
	    /* Literal match with following character. */
	    p++;
	    /* FALLTHROUGH */
	default:
	    if (*text != *p)
		return FALSE;
	    continue;
	case '?':
	    /* Match anything. */
	    continue;
	case '*':
	    while (*++p == '*' && (p - savep) < plen)
		/* Consecutive stars act just like one. */
		continue;
	    if (*p == '\0')
		/* Trailing star matches everything. */
		return TRUE;
	    while (*text)
		if ((matched = DoMatch(text++, p, (plen - (p - savep)))) != FALSE)
		    return matched;
	    return ABORT;
	case '[':
	    reverse = p[1] == NEGATE_CLASS ? TRUE : FALSE;
	    if (reverse)
		/* Inverted character class. */
		p++;
	    matched = FALSE;
	    if (p[1] == ']' || p[1] == '-')
		if (*++p == *text)
		    matched = TRUE;
	    for (last = *p; *++p && *p != ']' && (p - savep) < plen; last = *p)
		/* This next line requires a good C compiler. */
		if (*p == '-' && p[1] != ']'
		    ? *text <= *++p && *text >= last : *text == *p)
		    matched = TRUE;
	    if (matched == reverse)
		return FALSE;
	    continue;
	}
    }
    return *text == '\0';
}
