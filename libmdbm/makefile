# Makefile for libmdbm - multiple file dbm(3)
CFLAGS=	-O
OBJS=	mdbm.o
HDRS=	mdbm.h mdbm_local.h

all: libmdbm.a dbm

libmdbm.a: $(OBJS)
	ar cr $@ $(OBJS)
	ranlib $@

install:
	install -c libmdbm.a $(DESTDIR)/usr/lib
	ranlib $(DESTDIR)/usr/lib/libmdbm.a
	install -c mdbm.h $(DESTDIR)/usr/include
	install -c mdbm.3x $(DESTDIR)/usr/man/man3

dbm: dbm.o libmdbm.a
	$(CC) $(CFLAGS) -o $@ dbm.o libmdbm.a

clean:
	rm -f libmdbm.a *.o a.out dbm core

$(OBJS): $(HDRS)
