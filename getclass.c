#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "monitor.h"

static char *map;
static int shmid=-1;

char getclass(unsigned long addr)
{
	unsigned char bits, mask;
	unsigned int offs = (unsigned int)(ntohl(addr));
	offs >>= (32-MAXPREFIX);
	bits = (offs%(8/NBITS))*NBITS;
	mask = (0xff >> (8-NBITS))<<bits;
	offs /= (8/NBITS);
	return (map[offs] & mask) >> bits;;
}

static void freeshmem(void)
{
	struct shmid_ds buf;
	if (map)
	{	shmdt(map);
		map = NULL;
	}
	if (shmid != -1)
		if (shmctl(shmid, IPC_STAT, &buf) == 0)
			if (buf.shm_nattch == 0)
			{	shmctl(shmid, IPC_RMID, &buf);
				shmid = -1;
			}
}

void init_map(void)
{
	if (map) return;
	if (shmid==-1)
	{
		atexit(freeshmem);
		shmid = shmget(mapkey, MAPSIZE, 0444);
	}
	if (shmid != -1)
		map = shmat(shmid, NULL, SHM_RDONLY);
}
