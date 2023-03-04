/* plan 9 primitives */

static char lasterr[ERRMAX];

static off_t
size(int fd)
{
	Dir *stp = dirfstat(fd);
	off_t size = -1;

	if (stp != nil) {
		size = stp->length;
		free(stp);
	}
	return size;
}

static void
seterr(char *err)
{
	werrstr("%s", err);
}

static void
saverr(void)
{
	rerrstr(lasterr, sizeof lasterr);
}

static void
resterr(void)
{
	seterr(lasterr);
}

static int
openfile(char *name, int omode, int perm)
{
	int rwmode = omode & 3;
	int fd = open(name, rwmode);

	if (fd < 0 && rwmode != O_RDONLY)
		fd = create(name, rwmode, perm);
	return fd;
}
