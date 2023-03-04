/* Multiple-key database library (-lmdbm) using extensible hashing. */

#pragma	lib	"libmdbm.a"
#pragma	src	"/sys/src/libmdbm"

/* internal description of data & keys */
typedef struct {
	char	*dptr;
	short	dsize;		/* must fit within a pag block */
} datum;
typedef struct {
	unsigned short pagblksz;
	unsigned short dirblksz;
} Dbmparams;

typedef struct Dbm Dbm;

enum {
	/* flags to mdbmstore() */
	Mdbmnorepl,		/* insert only; abort if key found */
	Mdbmokrepl,		/* replace (or insert if not found) */

	/* visible flags */
	Mdbmimmwr = 1,		/* do all writes immediately (user-settable) */
	Mdbmreadonly = 2,	/* db is readonly */
};

int	mdbmclose(Dbm *d);
int	mdbmdelete(Dbm *d, datum key);
datum	mdbmfetch(Dbm *d, datum key);
datum	mdbmfirstkey(Dbm *d);
datum	mdbmnextkey(Dbm *d, datum key);
Dbm	*mdbmopen(char *, int omode, int perm, Dbmparams *);
int	mdbmstore(Dbm *d, datum key, datum dat, int repl);

void	mdbmbicflags(Dbm *m, int f);
void	mdbmbisflags(Dbm *m, int f);
int	mdbmgetflags(Dbm *m);
void	mdbmsetflags(Dbm *m, int f);
