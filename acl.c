#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "monitor.h"

static char *acl;
static char bit[8]={1, 2, 4, 8, 16, 32, 64, 128};

static int reload_one_acl(char **acl, char *acl_name)
{
  int i;
  char *newacl, *oldacl;
  unsigned long addr;
  FILE *facl;
  char str[2048];
  char *p;

  last_reload=time(NULL);
  facl=fopen(acl_name, "r");
  if (facl==NULL)
  { printf("Can't open %s: %s!\n", acl_name, strerror(errno));
    return -1;
  }
  newacl = calloc(1<<(24-3), 1);
  if (!newacl)
  { printf("Not enough core!\n");
    return -1;
  }
  while (fgets(str, sizeof(str), facl))
  {
    if (str[0]!='*') continue;
    for (p=str+3; isdigit(*p) || *p=='.'; p++);
    if (*p=='/') i=atoi(p+1);
    else i=24;
    if (i<0 || i>24) continue;
    *p='\0';
    addr=ntohl(inet_addr(str+3));
    if (addr==0) continue; /* default route */
    addr>>=8;
    if (i<=21)
    { addr>>=3;
      memset(newacl+addr, 255, 1<<(21-i));
    }
    else
    { int ndx=addr>>3, j;
      for (j=1<<(24-i); j>0; j--)
        newacl[ndx]|=bit[(addr++)%8];
    }
  }
  fclose(facl);
  oldacl=*acl;
  *acl=newacl;
  if (oldacl) free(oldacl);
  return (*acl ? 0 : 1);
}

int reload_acl(void)
{
  return reload_one_acl(&acl, ACLNAME);
}

int find_mask(unsigned long remote)
{
  remote=remote>>8;
  if ((remote & 0xffffe0) == 0x3e9500 ||
      (remote & 0xff0000) == 0x0a0000 ||
      (remote & 0xff0000) == 0x7f0000)
    return 2; /* local */
  if (acl[remote >> 3] & bit[remote & 7])
    return 1; /* ua */
  return 0;
}

#ifdef DEBUG
time_t last_reload;
char *uaname[]={"world","ua","local"};
int main(int argc, char *argv[])
{
  unsigned long addr;
  if (argc<2) return 0;
  addr=inet_addr(argv[1]);
  reload_acl();
  printf("%s\n", uaname[find_mask(ntohl(addr))]);
  return 0;
}
#endif
