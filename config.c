#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#else
#include <net/if.h>
#include <netinet/if_ether.h>
#endif
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
#include "monitor.h"

struct linktype *linkhead=NULL;
struct attrtype *attrhead=NULL;
char iface[32]=IFACE;
char logname[256]=LOGNAME, snapfile[256]=SNAPFILE, aclname[256]=ACLNAME;
char pidfile[256]=PIDFILE;
int write_interval=WRITE_INTERVAL, reload_interval=RELOAD_INTERVAL;
int maxmacs=MAXMACS, maxcoloip=MAXCOLOIP;
long mapkey;
int fromshmem;
char uaname[NCLASSES][32];
int  uaindex[NCLASSES];
#ifdef DO_MYSQL
char mysql_user[256], mysql_pwd[256], mysql_host[256];
char mysql_socket[256], mysql_db[256];
char mysql_table[256], mysql_utable[256], mysql_mtable[256], mysql_itable[256];
unsigned mysql_port;
#endif
#ifdef DO_PERL
char perlfile[256], perlstart[256], perlwrite[256];
char perlwritemac[256], perlstop[256];
#endif

#ifdef WITH_PORTS
static void read_port(char *p, u_short *port, u_short proto)
{
  if (isdigit(*p))
    *port=atoi(p);
  else
  { struct servent *se;
    struct protoent *pe;
    char *sproto=NULL;
    if (proto!=(u_short)-1)
      if ((pe=getprotobynumber(proto)) != NULL)
        sproto=pe->p_name;
    if ((se=getservbyname(p, sproto)) == NULL)
      printf("Unknown port %s\n", p);
    else
      *port=ntohs(se->s_port);
  }
}

static void read_ports(char *p, u_short *pl, u_short *pg, u_short proto)
{
  char c, *p1;

  for (p1=p; *p1 && !isspace(*p1) && *p1!=':'; p1++);
  c=*p1;
  *p1='\0';
  read_port(p, pl, proto);
  *p1=c;
  if (c!=':' || *pl==(u_short)-1)
  { *pg=*pl;
    return;
  }
  p=p1+1;
  for (p1=p; *p1 && !isspace(*p1); p1++);
  c=*p1;
  *p1='\0';
  read_port(p, pg, proto);
  *p1=c;
  if (*pg==(u_short)-1)
    *pg=*pl;
}
#endif

static void read_proto(char *p, u_short *proto)
{
  if (isdigit(*p))
    *proto=atoi(p);
  else
  {
    struct protoent *pe;
    char c, *p1;
    for (p1=p; *p1 && !isspace(*p1); p1++);
    c=*p1;
    *p1='\0';
    pe=getprotobyname(p);
    if (pe==NULL)
      printf("Unknown protocol %s\n", p);
    else
      *proto=pe->p_proto;
    *p1=c;
  }
}

int config(char *name)
{
  FILE *f;
  struct linktype *pl;
  struct attrtype *pa, *attrtail;
  char str[256];
  char *p, *p1;
  int  i, j;

  if (fromshmem) freeshmem();
  fromshmem=0;
  mapkey=MAPKEY;
#ifdef DO_PERL
  strcpy(perlfile,     "monitor.pl");
  strcpy(perlstart,    "startwrite");
  strcpy(perlwrite,    "write"     );
  strcpy(perlwritemac, "writemac"  );
  strcpy(perlstop,     "stopwrite" );
#endif
#ifdef DO_MYSQL
  mysql_user[0] = mysql_pwd[0] = mysql_host[0] = mysql_socket[0] = '\0';
  strcpy(mysql_db, "monitor_db");
  strcpy(mysql_table,  "traffic_%Y_%m");
  strcpy(mysql_mtable, "mac_%Y_%m");
  strcpy(mysql_itable, "arp");
  strcpy(mysql_utable, "users");
  mysql_port=0;
  mysql_start();
#endif
  f = fopen(name, "r");
  if (f==NULL)
  { fprintf(stderr, "Can't open %s: %s!\n", name, strerror(errno));
    return -1;
  }
  /* free links and attrs */
  if (linkhead)
  { for (pl=linkhead->next; pl; pl=pl->next)
    { free(linkhead);
      linkhead=pl;
    }
    free(linkhead);
    linkhead=NULL;
  }
  if (attrhead)
  { for (pa=attrhead->next; pa; pa=pa->next)
    { free(attrhead);
      attrhead=pa;
    }
    free(attrhead);
    attrhead=NULL;
  }
  attrtail = NULL;
  for (i=0; i<NCLASSES; i++)
  {
    uaindex[i]=i;
    snprintf(uaname[i], sizeof(uaname[i])-1, "class%u_", i);
  }
  while (fgets(str, sizeof(str), f))
  {
    p=strchr(str, '\n');
    if (p) *p='\0';
    p=strchr(str, '#');
    if (p) *p='\0';
    for (p=str; isspace(*p); p++);
    if (*p=='\0') continue;
    if (p!=str) strcpy(str, p);
    if (str[0]=='\0') continue;
    for (p=str+strlen(str)-1; isspace(*p); *p--='\0');
    p=str;
    if (strncmp(p, "mymac=", 6)==0)
    { short int m[3];
      sscanf(p+6, "%04hx.%04hx.%04hx", m, m+1, m+2);
      m[0] = htons(m[0]);
      m[1] = htons(m[1]);
      m[2] = htons(m[2]);
      memcpy(my_mac, m, sizeof(my_mac));
      continue;
    }
    if (strncmp(p, "iface=", 6)==0)
    { strncpy(iface, p+6, sizeof(iface)-1);
      continue;
    }
    if (strncmp(p, "log=", 4)==0)
    { strncpy(logname, p+4, sizeof(logname)-1);
      continue;
    }
    if (strncmp(p, "snap=", 5)==0)
    { strncpy(snapfile, p+5, sizeof(snapfile)-1);
      continue;
    }
    if (strncmp(p, "acl=", 4)==0)
    { strncpy(aclname, p+4, sizeof(aclname)-1);
      continue;
    }
    if (strncmp(p, "pid=", 4)==0)
    { strncpy(pidfile, p+4, sizeof(pidfile)-1);
      continue;
    }
    if (strncmp(p, "write-int=", 10)==0)
    { write_interval = atoi(p+10);
      if (write_interval == 0) write_interval=WRITE_INTERVAL;
      continue;
    }
    if (strncmp(p, "reload-int=", 11)==0)
    { reload_interval = atoi(p+11);
      if (reload_interval == 0) reload_interval=RELOAD_INTERVAL;
      continue;
    }
    if (strncmp(p, "maxmacs=", 8)==0)
    { maxmacs = atoi(p+8)*2;
      if (maxmacs == 0) maxmacs=MAXMACS;
      continue;
    }
    if (strncmp(p, "maxip=", 6)==0)
    { maxcoloip = atoi(p+6);
      if (maxcoloip == 0) maxcoloip=MAXCOLOIP;
      continue;
    }
    if (strncmp(p, "mapkey=", 7)==0)
    { mapkey = atol(p+7);
      if (mapkey == 0) mapkey=MAPKEY;
      fromshmem=1;
      continue;
    }
    if (strncmp(p, "fromshmem=", 10)==0)
    { if (p[10]=='n' || p[10]=='N' || p[10]=='0' || p[10]=='f' || p[10]=='F')
        fromshmem=0;
      else
        fromshmem=1;
      continue;
    }
    if (strncmp(p, "classes=", 8)==0)
    {
      p+=8;
      i=0;
      while (p && *p)
      { 
        if (i==NCLASSES)
        { fprintf(stderr, "Too many classes!\n");
          break;
        }
        for (p1=p; *p1 && !isspace(*p1) && *p1!=','; p1++);
        if (*p1) *p1++='\0';
        for (j=0; j<i; j++)
          if (strcmp(uaname[i], uaname[j]) == 0)
            break;
        uaindex[i]=j;
        if (j<i)
          uaname[i][0]='\0';
        else
          strncpy(uaname[i], p, sizeof(uaname[i])-1);
        for (p=p1; *p && (isspace(*p) || *p==','); p++);
        i++;
      }
      continue;
    }
#ifdef DO_PERL
    if (strncmp(p, "perlwrite=", 10)==0)
    { char *p1 = p+10;
      p=strstr(p1, "::");
      if (p==NULL)
      { printf("Incorrect perlwrite=%s ignored!", p1);
        continue;
      }
      *p=0;
      strncpy(perlfile, p1, sizeof(perlfile));
      strncpy(perlwrite, p+2, sizeof(perlwrite));
      continue;
    }
#endif
#ifdef DO_MYSQL
    if (strncmp(p, "mysql_user=", 11)==0)
    { strncpy(mysql_user, p+11, sizeof(mysql_user)-1);
      continue;
    }
    if (strncmp(p, "mysql_host=", 11)==0)
    { strncpy(mysql_host, p+11, sizeof(mysql_host)-1);
      p=strchr(mysql_host, ':');
      if (p)
      { mysql_port=atoi(p+1);
        *p=0;
      }
      continue;
    }
    if (strncmp(p, "mysql_pwd=", 10)==0)
    { strncpy(mysql_pwd, p+10, sizeof(mysql_pwd)-1);
      continue;
    }
    if (strncmp(p, "mysql_db=", 9)==0)
    { strncpy(mysql_db, p+9, sizeof(mysql_db)-1);
      continue;
    }
    if (strncmp(p, "mysql_socket=", 13)==0)
    { strncpy(mysql_socket, p+13, sizeof(mysql_socket)-1);
      continue;
    }
    if (strncmp(p, "mysql_table=", 12)==0)
    { strncpy(mysql_table, p+12, sizeof(mysql_table)-1);
      continue;
    }
    if (strncmp(p, "mysql_utable=", 13)==0)
    { strncpy(mysql_utable, p+13, sizeof(mysql_utable)-1);
      continue;
    }
    if (strncmp(p, "mysql_mtable=", 13)==0)
    { strncpy(mysql_mtable, p+13, sizeof(mysql_mtable)-1);
      continue;
    }
    if (strncmp(p, "mysql_itable=", 13)==0)
    { strncpy(mysql_itable, p+13, sizeof(mysql_itable)-1);
      continue;
    }
#endif
    for (p=str; *p && !isspace(*p); p++);
    if (*p) *p++='\0';
    if (strchr(str, '=')) continue; /* keyword */
    /* find link name */
    for (pl=linkhead; pl; pl=pl->next)
    { if (strcmp(pl->name, str)==0)
        break;
    }
    if (!pl && strcmp(str, "ignore"))
    { pl=calloc(1, sizeof(*pl));
      pl->next=linkhead;
      strcpy(pl->name, str);
      linkhead=pl;
    }
    /* create attribute structure */
    pa = calloc(1, sizeof(*pa));
    memset(pa, 0xff, sizeof(*pa));
    pa->link = pl;
    pa->next = NULL;
    pa->reverse=pa->fallthru=0;
    if (attrhead==NULL)
      attrhead = pa;
    else
      attrtail->next = pa;
    attrtail = pa;
    /* fill attribute structure */
    while (*p)
    { while (*p && isspace(*p)) p++;
      if (!*p) break;
      if (strncmp(p, "bymac", 5)==0)
      { if (pa->link->mactable==NULL)
          pa->link->mactable = calloc(MAXMACS, sizeof(struct mactype *));
      }
      else if (strncmp(p, "reverse", 7)==0)
      { pa->reverse=1;
      }
      else if (strncmp(p, "fallthru", 8)==0)
      { pa->fallthru=1;
      }
#ifndef NO_TRUNK
      else if (strncmp(p, "vlan=", 5)==0)
        pa->vlan=atoi(p+5);
#endif
      else if (strncmp(p, "proto=", 6)==0)
        read_proto(p+6, &pa->proto);
#ifdef WITH_PORTS
      else if (strncmp(p, "port=", 5)==0)
        read_ports(p+5, &pa->port1, &pa->port2, pa->proto);
      else if (strncmp(p, "localport=", 10)==0)
        read_ports(p+10, &pa->lport1, &pa->lport2, pa->proto);
#else
      else if (strncmp(p, "port=", 5)==0 || strncmp(p, "localport=", 10)==0)
        puts("Ports support is not compiled in, use 'configure --with-ports'");
#endif
      else if (strncmp(p, "mac=", 4)==0)
      { short int m[3];
        sscanf(p+4, "%04hx.%04hx.%04hx", m, m+1, m+2);
        m[0] = htons(m[0]);
        m[1] = htons(m[1]);
        m[2] = htons(m[2]);
        memcpy(pa->mac, m, sizeof(pa->mac));
      }
      else if (strncmp(p, "ip=", 3)==0)
      { char c, *p1;
        p+=3;
        for (p1=p; *p1 && (isdigit(*p1) || *p1=='.'); p1++);
        c=*p1;
        *p1='\0';
        pa->ip = ntohl(inet_addr(p));
        if (c=='/')
          pa->mask<<=(32-atoi(p1+1));
        *p1=c; p=p1;
        if ((pa->ip & pa->mask) != pa->ip)
        { unsigned long masked = (pa->ip & pa->mask);
          printf("Warning: %u.%u.%u.%u inconsistent with /%d (mask %u.%u.%u.%u)!\n",
                 ((char *)&(pa->ip))[3], ((char *)&(pa->ip))[2],
                 ((char *)&(pa->ip))[1], ((char *)&(pa->ip))[0],
                 atoi(p+1),
                 ((char *)&(pa->mask))[3], ((char *)&(pa->mask))[2],
                 ((char *)&(pa->mask))[1], ((char *)&(pa->mask))[0]);
          printf("ip & mask is %u.%u.%u.%u\n",
                 ((char *)&masked)[3], ((char *)&masked)[2],
                 ((char *)&masked)[1], ((char *)&masked)[0]);
        }
      }
      while (*p && !isspace(*p)) p++;
    }
  }
  fclose(f);
  if (fromshmem)
  { if (init_map())
    { printf("Can't init shared memory: %s\n", strerror(errno));
      return 1;
    }
  }
#ifdef DO_PERL
  exitperl();
  PerlStart();
#endif
  return 0;
}

