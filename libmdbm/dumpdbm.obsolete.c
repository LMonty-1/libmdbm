#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "mdbm.h"
#include "mdbm_local.h"

void
abort(void)
{
	kill(getpid(), SIGILL);
}

main(int argc, char **argv)
{
	int i, j, len, dsize, msize, blocks;
	Mdbm *mp;
	Pagblk *db;
	Pagent *de;
	struct stat sb;

	if (argc < 2) {
		fprintf(stderr, "Usage: dumpdbm dbname\n");
		exit(1);
	}
	if (argc > 2)
		signal(SIGILL, SIG_IGN);
	dsize = msize = 0;
	mp = mdbm_open(argv[1], O_RDONLY, 0, &dsize, &msize);
	if (!mp) {
		perror(argv[1]);
		exit(1);
	}
	printf("dbm %s: dsize = %d, msize = %d\n", argv[1], dsize, msize);
	(void) fstat(mp->pag.fd, &sb);
	blocks = sb.st_size/dsize;
	printf("(%d data blocks)\n", blocks);
	db = (Pagblk *) mp->pag.buf;
	for (i = 0; i < blocks; i++) {
		dread(mp, i);			/* internal routine! */
		printf("block %d: %d entries\n", i, db->nent);
		for (j = 0, de = db->ents; j < db->nent; j++, de++) {
			printf("\t%2d: @%4d links=%2d inx=%4d outx=%4d outh=%08x ",
				 j, de->txtoff, de->nlinks, de->inx,
				de->outx, de->outh);
			len = (j? de[-1].txtoff: dsize) - de->txtoff;
			pr_entry(mp->pag.buf+de->txtoff, len);
		}
	}
	(void) mdbm_close(mp);
	exit(0);
}

pr_entry(char *s, int len)
{
	int c;

	putchar('"');
	while (--len >= 0) {
		c = (unsigned char)*s++;
		if (c&0200)
			putchar('M'), putchar('-'), c &= 0177;
		if (c == 0177)
			putchar('^'), putchar('?');
		else if (c < ' ')
			putchar('^'), putchar(c+'@');
		else
			putchar(c);
	}
	putchar('"');
	putchar('\n');
}
