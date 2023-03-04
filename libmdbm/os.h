/* plan 9 headers & defines */
#include <u.h>
#include <libc.h>
#include <stdio.h>

typedef vlong off_t;

#define lseek seek

#define O_RDWR	 ORDWR
#define O_RDONLY OREAD
#define O_WRONLY OWRITE
#define O_CREAT	 128		/* fake, for openfile() */
