/* unix headers & defines */
static int lasterr;

static off_t
size(int fd)
{
	struct stat stat;

	if (fstat(fd, &stat) < 0)
		return -1;
	return stat.st_size;
}

static void
seterr(char *err)
{
	if (strcmp(err, "no mem") == 0)
		errno = ENOMEM;
	else if (strcmp(err, "invalid argument") == 0)
		errno = EINVAL;
	else if (strcmp(err, "permission denied") == 0)
		errno = EPERM;
	else if (strcmp(err, "out of space") == 0)
		errno = ENOSPC;
	else if (strcmp(err, "not found") == 0)
		errno = ENOENT;
	else
		errno = EINVAL;
}

static void
saverr(void)
{
	lasterr = errno;
}

static void
resterr(void)
{
	errno = lasterr;
}

static int
openfile(char *name, int omode, int perm)
{
	int fd = open(name, omode, perm);

	if (fd < 0 && (omode&3) != O_RDONLY) {
		close(creat(name, perm));
		fd = open(name, omode);
	}
	return fd;
}
