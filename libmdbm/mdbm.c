/* multi-key extensible hashing */
#include "os.h"
#include "mdbm.h"
#include "os.c"

#define MAGIC "#mdbm\n"

#define pagent(pb, n) ((Pagent *)((pb)->pagents + Pagsiz*(n)))

enum {
	Magic = 'd'<<8 | 'b',

	BYTESIZ = 8,			/* bits per byte */
	MAXUSHORT = (ushort)~0,

	Pagsiz = 4*2 + 4,   /* bytes per Pagent, excluding alignment padding */

	/* Def database block sizes for new databases */
	DefPagesiz = 1024,
	DefDirsiz  = 4096,

	/* Minimum sizes; smaller requests will be brought up to these values */
	MinPagesiz = 128,
	MinDirsiz  = MinPagesiz,

	Fdirty = 1,		/* fflag: buffer data is newer than file's */

	Userflags = Mdbmimmwr,  /* user allowed to modify only these flags */
};

/* an open mdbm file */
typedef struct {
	int	fd;		/* data area (page) file descriptor */
	int	size;		/* data buffer size */
	char	*buf;		/* current data block */
	char	*sec;		/* secondary data block (if any) */
	long	block;		/* index of current data block */
	off_t	dataoff;	/* base offset of data after header */
	char	fflags;
} Mdbmfile;

/* an open database (two files) */
struct Dbm {
	ushort	magic;
	char	flags;		/* flags (see below) */
	long	maxbit;		/* (max possible set bit in dir map) + 1 */
	Mdbmfile dir;		/* bit-mapped directory */
	Mdbmfile pag;		/* data pages */
};

typedef struct {
	off_t	block;
	short	byteoff;	/* bytes into current block */
	char	bitoff;		/* # of bits to shift left */
} Bitoffs;

/*
 * Header of the bit-mapped directory file; contains per-database info.
 * Is stored big-endian on disk.
 * Followed by bits set whenever a data block was split.
 */
typedef union {
	struct {
		char	magic[8];
		char	pagblksz[2];
		char	dirblksz[2];
	};
	char	pad[DefDirsiz];
} Dirhdr;

/*
 * The pages (data) file contains the following in each block: # of
 * entries in block, those entries, free space, and text.
 *
 * A (Pagent) entry contains off, links, inx, outx, outh.
 *
 * off is the offset within the block of the text (and thus also specifies
 * the size of the text string); links is the number of links to this item;
 * inx is the ``in index'' number of this item; outx is the ``out index''
 * number of this item; and outh is the out hash.
 *
 * If an item is in use as a key, its outx will be non-zero and repeated
 * in the inx field of its datum.  outh will (by the usual extensible hashing
 * rules) determine a block number, and the item with the matching inx field
 * in that block is the datum under the key in question.
 *
 * An item's inx field will always be non-zero and unique to the block in
 * which the item resides.
 */
typedef struct {
	char	txtoff[2];		/* offset to beginning of text */
	char	nlinks[2];		/* number of links */
	char	inx[2];			/* in index */
	char	outx[2];		/* out index */
	char	outh[4];		/* out hash */
} Pagent;
typedef struct {
	char	nent[2];		/* number of entries */
	char	pagents[1];
/*	Pagent	ents[1];	/* actually ents[nent] but can't say that */
} Pagblk;


/* big-endian get and put for shorts & longs */

static ushort
begets(void *p)
{
	uchar *up = (uchar *)p;

	return up[0]<<BYTESIZ | up[1];
}

static char *
beputs(void *vp, ushort s)
{
	char *p = (char *)vp;

	*p++ = s >> BYTESIZ;
	*p++ = s;
	return p;
}

static unsigned long
begetl(void *p)
{
	uchar *up = (uchar *)p;

	return up[0]<<(3*BYTESIZ) | up[1]<<(2*BYTESIZ) | up[2]<<BYTESIZ | up[3];
}

static char *
beputl(void *vp, unsigned long l)
{
	char *p = (char *)vp;

	*p++ = l >> (3*BYTESIZ);
	*p++ = l >> (2*BYTESIZ);
	*p++ = l >> BYTESIZ;
	*p++ = l;
	return p;
}

static int
notdbm(Dbm *d)
{
	return d == nil || d->magic != Magic;
}

void
mdbmbisflags(Dbm *m, int f)
{
	m->flags |= f & Userflags;
}

void
mdbmbicflags(Dbm *m, int f)
{
	m->flags &= ~(f & Userflags);
}

int
mdbmgetflags(Dbm *m)
{
	return m->flags;
}

void
mdbmsetflags(Dbm *m, int f)
{
	mdbmbicflags(m, Userflags);
	mdbmbisflags(m, f);
}

static void
badblk(char *buf, int size)
{
	fprintf(stderr, "mdbm: bad block\n");
	abort();
	memset(buf, 0, size);
}

/*
 * Perform some sanity checks on a data (page) block
 */
static void
chkblk(char *buf, int size)
{
	int i, t = size, nent, toff;
	Pagblk *pb = (Pagblk *)buf;
	Pagent *pe;

	nent = begets(pb->nent);
	pe = pagent(pb, 0);
	for (i = 0; i < nent; i++) {
		pe = pagent(pb, i);
		toff = begets(pe->txtoff);
		if (toff > t) {
			badblk(buf, size);
			return;
		}
		t = toff;
	}
	if (&buf[t] < (char *)pe)
		badblk(buf, size);
}

/* Read block blk (size sz offset off) from file f into buffer buf */
static int
rdblk(int f, off_t blk, char *buf, int sz, off_t off)
{
	lseek(f, blk*sz + off, 0);
	if (blk < 0)
		fprintf(stderr, "mdbm: negative block # (%lld) in rdblk\n", blk);
	return read(f, buf, sz);
}

/* Write block blk (size sz offset off) to file f from buffer buf */
static int
wrblk(int f, off_t blk, char *buf, int sz, off_t off)
{
	lseek(f, blk*sz + off, 0);
	if (blk < 0)
		fprintf(stderr, "mdbm: negative block # (%lld) in wrblk\n", blk);
	return write(f, buf, sz);
}

/* Write (if needed) */
static int
anysync(Mdbmfile *f)
{
	if (f->fflags & Fdirty)
		if (wrblk(f->fd, f->block, f->buf, f->size, f->dataoff) !=
		    f->size) {
			fprintf(stderr, "mdbm: write error\n");
			return -1;
		} else
			f->fflags &= ~Fdirty;
	return 0;
}

static int
syncall(Dbm *d)
{
	if ((anysync(&d->dir) < 0) | (anysync(&d->pag) < 0))
		return -1;
	return 0;
}

/* Do autowrites */
static int
autowrite(Dbm *d)
{
	if (d->flags & Mdbmimmwr)
		return syncall(d);
	return 0;
}

static int
readblock(Mdbmfile *mf, off_t b)
{
	int bytes;

	anysync(mf);
	memset(mf->buf, 0, mf->size);
	mf->block = b;
	/* short reads are okay */
	bytes = rdblk(mf->fd, b, mf->buf, mf->size, mf->dataoff);
	if (bytes < 0)
		fprintf(stderr, "mdbm: read error\n");
	return bytes;
}

static int
pagread(Dbm *d, off_t b)		/* Read pag block b */
{
	int bytes = 0;

	if (d->pag.block != b) {
		bytes = readblock(&d->pag, b);
		chkblk(d->pag.buf, d->pag.size);
	}
	return bytes;
}

static int
dirfread(Dbm *d, off_t b)		/* Read dir block b */
{
	int bytes = 0;

	if (d->dir.block != b)
		bytes = readblock(&d->dir, b);
	return bytes;
}

static int
ckhdr(Dirhdr *hp)
{
	if (strcmp(hp->magic, MAGIC) != 0) {
		fprintf(stderr, "mdbm: bad magic\n");
		return -1;
	}
	if (begets(hp->pagblksz) <= 0) {
		fprintf(stderr, "mdbm: bad pagblksz\n");
		return -1;
	}
	if (begets(hp->dirblksz) <= 0) {
		fprintf(stderr, "mdbm: bad dirblksz\n");
		return -1;
	}
	return 0;
}

static int
inbounds(int val, int def, int low, int high)
{
	if (val == 0)
		val = def;
	if (val < low)
		return low;
	if (val > high)
		return high;
	return val;
}

/* work out how big the buffers should be, if this is a new pb */
static void
sizebufs(Dirhdr *hp, Dbmparams *dpp)
{
	beputs(hp->pagblksz,
		inbounds(dpp->pagblksz, DefPagesiz, MinPagesiz, MAXUSHORT));
	beputs(hp->dirblksz,
		inbounds(dpp->dirblksz, DefDirsiz, MinDirsiz, MAXUSHORT));
}

static int
popfile(Mdbmfile *mf, char *base, char *ext, int omode, int perm)
{
	char *name = malloc(strlen(base) + strlen(ext) + 1);

	if (name == NULL)
		return mf->fd = -1;
	strcpy(name, base);
	strcat(name, ext);
	mf->dataoff = 0;
	mf->block = -1;
	mf->fd = openfile(name, omode, perm);
	free(name);
	return mf->fd;
}

/* internal version of mdbmopen */
static int
opendb(Dbm *d, char *file, int omode, int perm, Dbmparams *dpp)
{
	off_t fsize;
	Dirhdr hdr;
	Dbmparams dp;

	memset(d, 0, sizeof *d);
	d->dir.fd = d->pag.fd = -1;

	/* fix up the open mode, then open them files */
	if ((omode&3) == O_WRONLY)
		omode = (omode & ~3) | O_RDWR;
	d->flags = (omode&3) == O_RDONLY? Mdbmreadonly: 0;

	if (popfile(&d->pag, file, ".pag", omode, perm) < 0 ||
	    popfile(&d->dir, file, ".dir", omode, perm) < 0)
		return -1;
	d->dir.dataoff = sizeof hdr;

	if (dpp == NULL) {
		dp.pagblksz = DefPagesiz;
		dp.dirblksz = DefDirsiz;
		dpp = &dp;
	}
	fsize = size(d->dir.fd);
	if (fsize <= 0) {
		/* empty dir file: populate header */
		memset(&hdr, 0, sizeof hdr);
		strncpy(hdr.magic, MAGIC, sizeof hdr.magic);
		sizebufs(&hdr, dpp);
		if (!(d->flags&Mdbmreadonly) &&
		    write(d->dir.fd, (char *)&hdr, sizeof hdr) != sizeof hdr)
			return -1;
		lseek(d->dir.fd, 0, 0);		/* back over header */
		fsize = size(d->dir.fd);	/* file has grown */
	}
	d->maxbit = (fsize - sizeof hdr)*BYTESIZ;

	/* existing dir file: read header & validate */
	if (read(d->dir.fd, (char *)&hdr, sizeof hdr) != sizeof hdr ||
	    ckhdr(&hdr) < 0) {
		seterr("invalid argument");
		return -1;
	}

	/* allocate block buffers */
	d->dir.size = dpp->dirblksz = begets(hdr.dirblksz);
	d->pag.size = dpp->pagblksz = begets(hdr.pagblksz);
	if ((d->pag.buf = malloc(d->pag.size)) == NULL ||
	    (d->pag.sec = malloc(d->pag.size)) == NULL ||
	    (d->dir.buf = malloc(d->dir.size)) == NULL)
		return -1;
	return 0;
}

/* close all file descriptors and free all memory associated with d */
int
mdbmclose(Dbm *d)
{
	int rv;

	if (notdbm(d))
		return -1;
	rv = syncall(d);
	d->magic = 0;
	if (d->pag.fd >= 0 && close(d->pag.fd) < 0)
		rv = -1;
	if (d->dir.fd >= 0 && close(d->dir.fd) < 0)
		rv = -1;
	free(d->pag.buf);
	free(d->pag.sec);
	free(d->dir.buf);
	free(d);
	return rv;
}

/* Open or create a database */
Dbm *
mdbmopen(char *file, int omode, int perm, Dbmparams *dpp)
{
	Dbm *d = (Dbm *)malloc(sizeof *d);

	if (d == NULL)
		return NULL;
	if (opendb(d, file, omode, perm, dpp) < 0) {
		saverr();
		mdbmclose(d);
		resterr();
		return NULL;
	}
	d->magic = Magic;
	return d;
}

static Bitoffs
getbitoffs(Dbm *d, unsigned long bitno)
{
	off_t bn;
	Bitoffs bo;

	if (bitno >= d->maxbit) {
		memset(&bo, 0, sizeof bo);
		return bo;
	}
	bo.bitoff = bitno % BYTESIZ;
	bn = bitno / BYTESIZ;		/* byte index */
	bo.byteoff = bn % d->dir.size;
	bo.block =   bn / d->dir.size;
	return bo;
}

/* returns -1 on I/O error, else the bit requested */
static int
getbit(Dbm *d, unsigned long bitno)
{
	if (bitno < d->maxbit) {
		Bitoffs bo = getbitoffs(d, bitno);

		if (dirfread(d, bo.block) < 0)
			return -1;
		return (d->dir.buf[bo.byteoff] >> bo.bitoff) & 1;
	}
	return 0;
}

/*
 * Mark the block as having been split by setting the appropriate bit
 * in the dir map.
 *
 * returns -1 on I/O error.
 */
static int
setbit(Dbm *d, unsigned long bitno)
{
	Bitoffs bo;

	if (bitno >= d->maxbit) {
		d->maxbit = bitno + 1;
		if (getbit(d, bitno) < 0)
			return -1;
	}
	bo = getbitoffs(d, bitno);
	d->dir.buf[bo.byteoff] |= 1 << bo.bitoff;
	d->dir.fflags |= Fdirty;
	return 0;
}

/*
 * Read in the appropriate data block for an item whose hash index is hash.
 * The hash index specifies the data block in an indirect way:
 * if the bit in the dir map is set, then more bits of the hash value should
 * be considered.  If it is not set then we have the right hash bits
 * and the block number is just the low bits of the hash value.
 *
 * Return the hash mask that gets the right block number.
 */
static int
mdbmaccess(Dbm *d, long hash)
{
	int bit;
	long hmask;

	for (hmask = 0; ; hmask = (hmask<<1) + 1) {
		bit = getbit(d, (hash & hmask) + hmask);
		if (bit < 0)
			return -1;
		if (!bit)
			break;
	}
	if (pagread(d, hash & hmask) < 0)
		return -1;
	return hmask;
}

/*
 * Return the next hash number for this dbm, or 0 for no more
 */
static long
mdbmhashinc(long hash, long hmask)
{
	long bit;

	hash &= hmask;
	bit = hmask + 1;
	for (; ; ) {
		bit >>= 1;
		if (bit == 0)
			return 0;
		if ((hash&bit) == 0)
			return hash|bit;
		hash &= ~bit;
	}
	return 0;
}

static datum nildatum;

/*
 * Return the first datum in dbm d with hash value hash
 */
static datum
mdbmfirsthash(Dbm *d, long hash)
{
	int bl = 0, i, il, found, nent, toff;
	long hmask;
	char *bp = NULL, *ip;
	datum rval;
	Pagent *pe;
	Pagblk *pb = (Pagblk *)d->pag.buf;

	for (; ; ) {
		/*
		 * Suck in the block for the given hash,
		 * then find the "first" key.
		 */
		hmask = mdbmaccess(d, hash);
		if (hmask == -1)
			return nildatum;
		found = 0;
		nent = begets(pb->nent);
		for (i = 0; i < nent; i++) {
			pe = pagent(pb, i);
			if (begets(pe->outx) == 0)	/* not a key */
				continue;
			toff = begets(pe->txtoff);
			il = (i? begets(pagent(pb, i-1)->txtoff): d->pag.size) -
				toff;
			ip = d->pag.buf + toff;
			if (!found || il < bl ||
			    (il == bl && memcmp(ip, bp, il) < 0)) {
				bl = il;
				bp = ip;
				found++;
			}
		}
		if (found) {
			memmove(rval.dptr = d->pag.sec, bp, rval.dsize = bl);
			return rval;
		}

		/* No item with this hash, so get next hash and try again */
		hash = mdbmhashinc(hash, hmask);
		if (hash == 0)		/* no more */
			return nildatum;
	}
}

/*
 * Return the "first" key in dbm d
 */
datum
mdbmfirstkey(Dbm *d)
{
	if (notdbm(d))
		return nildatum;
	return mdbmfirsthash(d, 0);
}

static int hitab[16] = {
/* ken's
	055,043,036,054,063,014,004,005,
	010,064,077,000,035,027,025,071, */

	61, 57, 53, 49, 45, 41, 37, 33,
	29, 25, 21, 17, 13,  9,  5,  1,
};

static long hltab[64] = {
	06100151277L,06106161736L,06452611562L,05001724107L,
	02614772546L,04120731531L,04665262210L,07347467531L,
	06735253126L,06042345173L,03072226605L,01464164730L,
	03247435524L,07652510057L,01546775256L,05714532133L,
	06173260402L,07517101630L,02431460343L,01743245566L,
	00261675137L,02433103631L,03421772437L,04447707466L,
	04435620103L,03757017115L,03641531772L,06767633246L,
	02673230344L,00260612216L,04133454451L,00615531516L,
	06137717526L,02574116560L,02304023373L,07061702261L,
	05153031405L,05322056705L,07401116734L,06552375715L,
	06165233473L,05311063631L,01212221723L,01052267235L,
	06000615237L,01075222665L,06330216006L,04402355630L,
	01451177262L,02000133436L,06025467062L,07121076461L,
	03123433522L,01010635225L,01716177066L,05161746527L,
	01736635071L,06243505026L,03637211610L,01756474365L,
	04723077174L,03642763134L,05750130273L,03655541561L,
};

/*
 * Calculate the hash val for the given item.
 */
static long
mdbmcalchash(char *s, int len)
{
	int j, hashi = 0;
	long hashl = 0;

	while (--len >= 0) {
		int f = *s++;

		for (j = 0; j < BYTESIZ; j += 4) {
			hashi += hitab[f&017];
			hashl += hltab[hashi&077];
			f >>= 4;
		}
	}
	return hashl;
}

/*
 * Return the "next" key in dbm d
 */
datum
mdbmnextkey(Dbm *d, datum key)
{
	int bl = 0, i, il, found, nent, toff;
	long hash, hmask;
	char *bp = NULL, *ip;
	Pagent *pe;
	Pagblk *pb;
	datum rval;

	if (notdbm(d))
		return nildatum;
	pb = (Pagblk *)d->pag.buf;
	/*
	 * Suck in the block for the given hash,
	 * then find the key that follows the one given.
	 */
	hash = mdbmcalchash(key.dptr, key.dsize);
	hmask = mdbmaccess(d, hash);
	if (hmask == -1)
		return nildatum;
	found = 0;
	nent = begets(pb->nent);
	for (i = 0; i < nent; i++) {
		pe = pagent(pb, i);
		if (begets(pe->outx) == 0)		/* not a key */
			continue;
		toff = begets(pe->txtoff);
		il = (i? begets(pagent(pb, i-1)->txtoff): d->pag.size) - toff;
		ip = d->pag.buf + toff;
		if (il < key.dsize ||
		    (il == key.dsize && memcmp(ip, key.dptr, il) <= 0))
			continue;
		if (!found || il < bl ||
		    (il == bl && memcmp(ip, bp, il) < 0)) {
			bl = il;
			bp = ip;
			found++;
		}
	}
	if (found) {
		memmove(rval.dptr = d->pag.sec, bp, rval.dsize = bl);
		return rval;
	}

	/* No item with this hash, so get next hash and return its first item */
	hash = mdbmhashinc(hash, hmask);
	if (hash == 0)			/* no more */
		return nildatum;
	return mdbmfirsthash(d, hash);
}

/*
 * Search for the given key, and if found, return a pointer to the
 * datum under the key.  If ablock and aindex are nonzero, fill in
 * the block and index numbers of the key.  If justkey is true,
 * forget about the datum and stop when the key is found.
 *
 * (Workhorse for fetch, also used by delete & store.)
 */
static Pagent *
mdbmsearch(Dbm *d, char *s, int len, long *ablock, int *aindex, int justkey)
{
	int i, nent, toff;
	ushort outx;
	long outh;
	Pagent *pe;
	Pagblk *pb = (Pagblk *)d->pag.buf;

	if (mdbmaccess(d, mdbmcalchash(s, len)) == -1)
		return NULL;
	nent = begets(pb->nent);
	pe = pagent(pb, 0);
	for (i = 0; i < nent; i++) {
		pe = pagent(pb, i);
		if (begets(pe->outx) == 0)		/* not a key */
			continue;
		toff = begets(pe->txtoff);
		if ((i? begets(pagent(pb, i-1)->txtoff): d->pag.size) - toff ==
		    len && memcmp(s, d->pag.buf + toff, len) == 0)
			break;
	}
	if (i >= nent)
		return NULL;
	if (ablock)
		*ablock = d->pag.block;
	if (aindex)
		*aindex = i;
	if (justkey)
		return pe;
	outx = begets(pe->outx);
	outh = begetl(pe->outh);
	if (mdbmaccess(d, outh) == -1)
		return NULL;
	for (i = 0; i < nent; i++) {
		pe = pagent(pb, i);
		if (begets(pe->inx) == outx)
			return pe;
	}
	fprintf(stderr, "mdbm bug: no datum for key (%d, %d)\n", outh, outx);
	return NULL;
}

/*
 * Find datum in dbm d, given key
 */
datum
mdbmfetch(Dbm *d, datum key)
{
	int toff;
	Pagent *pe;
	Pagblk *pb;
	datum item;

	if (notdbm(d))
		return nildatum;
	pb = (Pagblk *)d->pag.buf;
	memset(&item, 0, sizeof item);
	item.dptr = NULL;		/* paranoia */
	pe = mdbmsearch(d, key.dptr, key.dsize, (long *)0, (int *)0, 0);
	if (pe) {
		toff = begets(pe->txtoff);
		item.dptr = d->pag.buf + toff;
		item.dsize = (pe > (Pagent *)pb->pagents?
			begets(((Pagent *)((char *)pe - Pagsiz))->txtoff):
			d->pag.size) - toff;
	}
	return item;
}

/*
 * Exhaustively search for a valid inx index number for the new entry
 * in d.  We "guarantee" that one such will be available.  (Used by
 * dostore)
 */
static ushort
mdbminx(Dbm *d)
{
	Pagblk *pb = (Pagblk *)d->pag.buf;
	int i, n = begets(pb->nent) - 1, ent;
	ushort inx;

	for (inx = 1; ; inx++) {
		for (i = n, ent = 0; --i >= 0; ent++)
			if (begets(pagent(pb, ent)->inx) == inx)
				break;
		if (i < 0)
			return inx;
		if (inx == MAXUSHORT)
			break;
	}
	fprintf(stderr, "mdbm bug: no inx's available (can't happen)\n");
	abort();
	return 1;
}

/*
 * Add an item to a data block, returning a pointer to the dentry
 * descriptor (or 0 if it doesn't fit).  The caller will fill in all
 * fields except the offset, and will fill in the text of the item.
 */
static Pagent *
additem(char *buf, int dsize, int len)
{
	Pagblk *pb = (Pagblk *)buf;
	int i = begets(pb->nent);
	Pagent *pe;

	/*
	 * Figure out where the text should go.  If there are no
	 * entries in this block, it will go at the end of the block;
	 * otherwise, it will go right before the last entry.
	 * It must not cross over the entry descriptor area,
	 * which will be one larger than it is now.
	 */
	pe = pagent(pb, i);
	i = (i? begets(pagent(pb, i-1)->txtoff): dsize) - len;
	if (buf+i < (char *)pe + Pagsiz)
		return 0;

	beputs(pb->nent, begets(pb->nent) + 1);
	beputs(pe->txtoff, i);
	return pe;
}

/*
 * Delete item 'n' from current data buffer of dbm d
 */
static int
mdbmdelitem(Dbm *d, int n)
{
	int i, nlinks, nent, toff, prevtoff = 0, nenttoff;
	Pagent *pe, *e;
	Pagblk *pb = (Pagblk *)d->pag.buf;

	nent = begets(pb->nent);
	if (n < 0 || n >= nent) {
		fprintf(stderr, "mdbm bug: bad delitem\n");
		abort();
		return -1;
	}
	pe = pagent(pb, n);
	nlinks = begets(pe->nlinks);
	if (nlinks > 1) {
		beputs(pe->nlinks, --nlinks);
		d->pag.fflags |= Fdirty;
		return 0;
	}
	beputs(pb->nent, --nent);
	toff = begets(pe->txtoff);
	if (n)
		prevtoff = begets(pagent(pb, n-1)->txtoff);
	i = (n? prevtoff: d->pag.size) - toff;
	if (i) {			/* delete i bytes of text */
		nenttoff = begets(pagent(pb, nent)->txtoff);
		if (n < nent) {
			char *to = d->pag.buf +(n? prevtoff: d->pag.size);
			int bytes = toff - nenttoff;

			if (bytes > 0)
				memmove(to, to - i, bytes);
		}
		nenttoff = begets(pagent(pb, nent)->txtoff);
		memset(d->pag.buf + nenttoff, 0, i);
	}
	for (e = pagent(pb, nent); pe < e; n++) {
		pe = pagent(pb, n);
		memmove(pe, pagent(pb, n+1), sizeof *pe);
		beputs(pe->txtoff, begets(pe->txtoff) + i);
	}
	memset(e, 0, sizeof *pe);
	return 0;
}

/*
 * Actually store the text of an item in a dblock.  Fill in the supplied
 * pointer (if any) with the hash number of the item.  Also, if a split
 * occurs, check *asplit, and if the block numbers match, set *asplit,
 * otherwise clear it.  (Used by mdbmstore)
 */
static Pagent *
dostore(Dbm *d, char *s, int len, long *ahash, long *asplit)
{
	int i, l, rlen, nent, toff, inx;
	unsigned minx = MAXUSHORT, maxx = 0;
	long hash, hmask, IfSplit = 0;
	char *p;
	Pagent *pe;
	Pagblk *pb = (Pagblk *)d->pag.buf;

	hash = mdbmcalchash(s, len);
	if (ahash)
		*ahash = hash;
	if (asplit) {
		IfSplit = *asplit;
		*asplit = 0;
	}
	while ((hmask = mdbmaccess(d, hash)) != -1) {
		rlen = len;
		nent = begets(pb->nent);
		for (i = 0; i < nent; i++) {
			pe = pagent(pb, i);
			toff = begets(pe->txtoff);
			if ((i? begets(pagent(pb, i-1)->txtoff): d->pag.size) -
			    toff == rlen &&
			    memcmp(s, d->pag.buf + toff, rlen) == 0) {
				beputs(pe->nlinks, begets(pe->nlinks) + 1);
				d->pag.fflags |= Fdirty;
				return pe;
			}
			inx = begets(pe->inx);
			if (inx < minx)
				minx = inx;
			if (inx > maxx)
				maxx = inx;
		}
		pe = additem(d->pag.buf, d->pag.size, rlen);
		if (pe) {
			beputs(pe->nlinks, 1); /* will be either key or datum */
			beputs(pe->outx, 0); /* not a key (at least, not yet) */

			/*
			 * inx will be one less than min inx (if possible),
			 * or one more than max inx (if possible), that occur
			 * in the block.  If none of those yield results,
			 * we perform an exhaustive search.  Hopefully the
			 * searches are rare.
			 */
			if (i == 0)
				inx = 1;	/* 1st one, special case */
			else if (minx < MAXUSHORT && minx > 1)
				inx = minx-1;
			else if (maxx && maxx < MAXUSHORT)
				inx = maxx+1;
			else
				inx = mdbminx(d);
			beputs(pe->inx, inx);
			memmove(d->pag.buf + begets(pe->txtoff), s, len);
			d->pag.fflags |= Fdirty;
			return pe;
		}

		/*
		 * Didn't fit; split the block to make room.
		 * Presumably about half of the existing entries
		 * will move to the new block.
		 */
		if (len + sizeof *pb > d->pag.size)
			return NULL;			/* hopeless! */
		/*
		 * If we are splitting the "interesting" block,
		 * make a note of that.
		 */
		if (asplit && IfSplit == d->pag.block)
			*asplit = 1;
		memset(d->pag.sec, 0, d->pag.size);
		hmask++;

		nent = begets(pb->nent);
		for (i = 0; i < nent; ) {
			pe = pagent(pb, i);
			toff = begets(pe->txtoff);
			l = (i? begets(pagent(pb, i-1)->txtoff): d->pag.size) -
				toff;
			p = d->pag.buf + toff;
			if (mdbmcalchash(p, l) & hmask) {
				Pagent *npe=additem(d->pag.sec, d->pag.size, l);

				memmove(d->pag.sec + begets(npe->txtoff), p, l);
				/* no need to byte-swap when just copying */
				memmove(npe->nlinks, pe->nlinks,
					sizeof pe->nlinks);
				memmove(npe->inx, pe->inx, sizeof pe->inx);
				memmove(npe->outx, pe->outx, sizeof pe->outx);
				memmove(npe->outh, pe->outh, sizeof pe->outh);
				/* force mdbmdelitem to remove it */
				beputs(pe->nlinks, 1);
				mdbmdelitem(d, pe - (Pagent *)pb->pagents);
			} else
				i++;
		}
		wrblk(d->pag.fd, d->pag.block+hmask, d->pag.sec, d->pag.size, 0);
		d->pag.fflags |= Fdirty;
		hmask--;

		/*
		 * Now mark the block as having been split by setting the
		 * appropriate bit in the dir map.
		 */
		if (setbit(d, (hash & hmask) + hmask) < 0)
			return NULL;
	}
	return NULL;
}

static int
notwritable(Dbm *d)
{
	if (d->flags&Mdbmreadonly) {
		seterr("permission denied");
		return 1;
	}
	return 0;
}

static int
delkey(Dbm *d, long keyblock, int keyindex)
{
	Pagblk *pb;

	if (notdbm(d) || pagread(d, keyblock) < 0)
		return -1;
	pb = (Pagblk *)d->pag.buf;
	beputs(pagent(pb, keyindex)->outx, 0);		/* not a key anymore */
	mdbmdelitem(d, keyindex);
	autowrite(d);
	return 0;
}

/*
 * Store dat as datum of key key in dbm d.
 * replace: true → overwrite if exists.
 */
int
mdbmstore(Dbm *d, datum key, datum dat, int replace)
{
	int keyindex;
	ushort outx = 0;
	long didsplit, keyblock, outh;
	Pagent *pe;
	Pagblk *pb;

	if (notdbm(d) || notwritable(d))
		return -1;
	pb = (Pagblk *)d->pag.buf;
	/*
	 * Search for the key's datum.  If it is found, then delete the datum
	 * (unless we are told not to) and store a new one, then modify the
	 * key's description parameters to point to the new datum.
	 * If it is not found, then presumably there is no such key,
	 * so make a new one, then proceed as before.
	 */
	pe = mdbmsearch(d, key.dptr, key.dsize, &keyblock, &keyindex, 0);
	if (pe) {
		if (!replace)
			return 1;
		mdbmdelitem(d, pe - (Pagent *)pb->pagents);
		/* now committed; if new datum doesn't fit, old pairing is gone! */
	} else {				/* create new key */
		pe = dostore(d, key.dptr, key.dsize, (long *)0, (long *)0);
		if (pe == 0) {
			autowrite(d);
			seterr("out of space");	/* presumably */
			return -1;
		}
		beputs(pe->outx, 1);	/* force it to look like a key */
		keyblock = d->pag.block;
		keyindex = pe - (Pagent *)pb->pagents;
	}
	didsplit = keyblock;
	pe = dostore(d, dat.dptr, dat.dsize, &outh, &didsplit);
	if (pe)
		outx = begets(pe->inx);
	/* if the data store split the key's block, must find the key again */
	if (didsplit)
		if (mdbmsearch(d, key.dptr, key.dsize, &keyblock, &keyindex, 1)
		    == 0) {
			fprintf(stderr,
				"mdbm bug: post-split keysearch failed!\n");
			abort();
		}
	if (!pe) {				/* oops, go delete the key */
		if (delkey(d, keyblock, keyindex) < 0)
			return -1;
		seterr("out of space");
		return -1;
	}
	/*
	 * Replace the outx and outh numbers in the old (or new) key
	 * so that it points to the new datum.
	 */
	if (pagread(d, keyblock) < 0)
		return -1;
	pe = pagent(pb, keyindex);
	beputl(pe->outh, outh);
	beputs(pe->outx, outx);
	d->pag.fflags |= Fdirty;
	autowrite(d);
	return 0;
}

/*
 * Sync the file attached to dbm d
 */
int
mdbmsync(Dbm *d)
{
	int rv;

	if (notdbm(d))
		return -1;
	rv = syncall(d);
#ifdef unix
	(void) fsync(d->pag.fd);
	(void) fsync(d->dir.fd);
#endif
	return rv;
}

/*
 * Delete datum under key in dbm d
 */
int
mdbmdelete(Dbm *d, datum key)
{
	int keyindex, datindex;
	long keyblock;
	Pagent *pe;
	Pagblk *pb;

	if (notdbm(d))
		return -1;
	pe = mdbmsearch(d, key.dptr, key.dsize, &keyblock, &keyindex, 0);
	if (pe == 0) {
		seterr("not found");
		return -1;
	}
	if (notwritable(d))
		return -1;

	/*
	 * Delete the datum.  This might change the position of the key, so
	 * check, and if so, fix up keyindex ahead of time.
	 */
	pb = (Pagblk *)d->pag.buf;
	datindex = pe - (Pagent *)pb->pagents;
	if (d->pag.block == keyblock && datindex < keyindex &&
	    begets(pe->nlinks) == 1)
		keyindex--;
	mdbmdelitem(d, datindex);

	/* delete the key */
	if (delkey(d, keyindex, keyblock) < 0)
		return -1;
	return 0;
}
