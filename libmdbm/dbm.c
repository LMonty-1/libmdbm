/*
 * 9testdbm - exercise the multiple-key, extensible-hashing database library
 */

#include "os.h"
#include <ctype.h>
#include "mdbm.h"

#define exit(n) exits((n) == 0? NULL: "error")

/* $Header: testdbm.c,v 1.3 84/09/10 01:57:33 geoff Exp $ */

enum { NAV = 10, };

static Dbm *mp;
static int prompt = 1;
static struct stringarg {
	int	s_len;
	char	*s_str;
} av[NAV];

void c_open(int), c_close(int), c_fetch(int), c_insert(int), c_replace(int);
void c_delete(int), c_list(int), c_quit(int), c_sync(int);

static struct cmd {
	char	*c_name;
	void	(*c_func)(int);
	short	c_args;
} cmds[] = {
	"open",		c_open,		2,
	"open",		c_open,		4,
	"open",		c_open,		5,
	"close",	c_close,	1,
	"fetch",	c_fetch,	2,
	"store",	c_insert,	3,
	"replace",	c_replace,	3,
	"delete",	c_delete,	2,
	"list",		c_list,		1,
	"quit",		c_quit,		1,
	"sync",		c_sync,		1,
	0, 0, 0
};

#define checkdb() \
	if (!mp) { \
		fprintf(stderr, "no database active\n"); \
		return; \
	}

static int
parse(char *s)
{
	int aleft, c, qu;
	char *cp;
	struct stringarg *ap;
	static char xbuf[BUFSIZ];

	for (ap = av, aleft = NAV; --aleft >= 0; ap++)
		if (ap->s_str) {
			free(ap->s_str);
			ap->s_str = NULL;
		}

	aleft = NAV;
	for (ap = av; *s; ap++) {
		while (isspace(*s))
			s++;
		if (!*s)
			break;
		qu = 0;
		cp = xbuf;
		while ((c = *s++) != 0 && (qu || !isspace(c)))
			if (qu == '\\') {
				switch (c) {
				case 'n':
					c = '\n';
					break;
				case 'r':
					c = '\r';
					break;
				case 't':
					c = '\t';
					break;
				case 'b':
					c = '\b';
					break;
				case 'f':
					c = '\f';
					break;
				case '0': case '1': case '2': case '3':
				case '4': case '5': case '6': case '7':
					c -= '0';
					if (*s >= '0' && *s <= '7') {
						c = (c<<3) + *s++ -'0';
						if (*s >= '0' && *s <= '7')
							c = (c<<3) + *s++ -'0';
					}
					break;
				}
				*cp++ = c;
				qu = 0;
			} else if (c == qu)
				qu = 0;
			else if (qu == 0 && (c == '\'' || c == '"' || c == '\\'))
				qu = c;
			else
				*cp++ = c;
		--s;
		*cp++ = 0;
		if (--aleft < 0) {
			fprintf(stderr, "too many args's\n");
			return 0;
		}
		ap->s_str = malloc(cp - xbuf);
		if (ap->s_str == NULL) {
			perror("malloc");
			exit(1);
		}
		ap->s_len = cp - xbuf;
		memmove(ap->s_str, xbuf, ap->s_len);
		ap->s_len--;		/* stop counting trailing \0 */
	}
	return NAV - aleft;
}

static int
doit(char *s)
{
	int argc = parse(s);
	struct cmd *cp;

	if (argc < 1)
		return 0;
	if (av[0].s_len < 1)
		return 1;
	for (cp = cmds; cp->c_name; cp++)
		if (cp->c_args != argc)
			continue;
		else if (strncmp(cp->c_name, av[0].s_str, av[0].s_len) == 0) {
			(*cp->c_func)(argc);
			return 0;
		}
	return 1;
}

void
c_quit(int)
{
	if (mp)
		(void) mdbmclose(mp);
	exit(0);
}

void
main(int argc, char **argv)
{
	int errflg = 0;
	char cmdbuf[BUFSIZ];

	ARGBEGIN {
	case 'p':
		prompt = 0;
		break;
	default:
		errflg++;
		break;
	} ARGEND
	if (errflg) {
		fprintf(stderr, "usage: %s [-p]\m", argv0);
		exit(0);
	}

	setbuf(stderr, NULL);
	setbuf(stdout, NULL);
	for (; ; ) {
		if (prompt)
			printf("> ");
		if (fgets(cmdbuf, sizeof cmdbuf, stdin) == NULL)
			break;
		if (doit(cmdbuf))
			printf(
		"cmds: open close fetch store replace delete list sync quit\n");
	}
	putchar('\n');
	c_quit(0);
}

void
c_open(int argc)
{
	Dbmparams dp;

	memset(&dp, 0, sizeof dp);
	c_close(0);
	if (argc >= 4) {
		dp.pagblksz = atoi(av[2].s_str);
		dp.dirblksz = atoi(av[3].s_str);
	}
	mp = mdbmopen(av[1].s_str, O_RDWR|O_CREAT, 0666, &dp);
	if (mp == NULL) {
		perror(av[1].s_str);
		return;
	}
	printf("opened %s - pagblksz %d, dirblksz %d\n",
		av[1].s_str, dp.pagblksz, dp.dirblksz);
}

void
c_close(int)
{
	if (mp)
		(void) mdbmclose(mp);
	mp = NULL;
}

/* bug: won't cope with NULs in the datum */
void
prdatum(datum d)
{
	printf("%.*s", d.dsize, d.dptr);
}

static void
getkey(datum *key)
{
	key->dptr  = av[1].s_str;
	key->dsize = av[1].s_len;
}

static void
getkeydat(datum *key, datum *dat)
{
	getkey(key);
	dat->dptr  = av[2].s_str;
	dat->dsize = av[2].s_len;
}

void
c_fetch(int)
{
	datum key, dat;

	checkdb();
	getkey(&key);
	dat = mdbmfetch(mp, key);
	if (dat.dptr == nil)
		fprintf(stderr, "%s: not found\n", key.dptr);
	else {
		prdatum(key);
		printf(": ");
		prdatum(dat);
		putchar('\n');
	}
}

void
c_insert(int)
{
	int e;
	datum key, dat;

	checkdb();
	getkeydat(&key, &dat);
	e = mdbmstore(mp, key, dat, Mdbmnorepl);
	if (e < 0)
		fprintf(stderr, "%s: store failed\n", key.dptr);
	else if (e > 0)
		fprintf(stderr, "%s: insert failed, key in use\n", key.dptr);
}

void
c_replace(int)
{
	datum key, dat;

	checkdb();
	getkeydat(&key, &dat);
	if (mdbmstore(mp, key, dat, Mdbmokrepl))
		fprintf(stderr, "%s: replace failed\n", key.dptr);
}

void
c_delete(int)
{
	datum key;

	checkdb();
	getkey(&key);
	if (mdbmdelete(mp, key))
		fprintf(stderr, "%s: delete failed\n", key.dptr);
}

void
c_list(int)
{
	datum key, dat;

	checkdb();
	for (key = mdbmfirstkey(mp); key.dptr; key = mdbmnextkey(mp, key)) {
		dat = mdbmfetch(mp, key);
		if (dat.dptr == nil)
			fprintf(stderr, "%.*s: key not found\n",
				key.dsize, key.dptr);
		else {
			prdatum(key);
			printf(": ");
			prdatum(dat);
			putchar('\n');
		}
	}
}

int	mdbmsync(Dbm *d);

void
c_sync(int)
{
	checkdb();
	mdbmsync(mp);
}
