#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

#ifndef SIGINFO
#define SIGINFO SIGIO
#endif

u_char my_mac[ETHER_ADDR_LEN]={MYMAC};
static char *uaname[NCLASSES]={"world","ua"};
extern long snap_traf;
extern FILE *fsnap;

void add_stat(u_char *src_mac, u_char *dst_mac, u_long src_ip, u_long dst_ip,
              u_long len,
#ifndef NO_TRUNK
              int vlan,
#endif
#ifdef HAVE_PKT_TYPE
              int in,
#endif
              int proto)
{
  u_long local=0, remote=0;
  u_char *remote_mac=NULL;
  int src_ua, dst_ua, key, leftpacket, find;
#ifndef HAVE_PKT_TYPE
  int in=0;
#endif
  struct attrtype *pa;
  sigset_t set, oset;
  struct mactype **mactable;

  src_ip = ntohl(src_ip);
  dst_ip = ntohl(dst_ip);
  if (dst_mac)
  { if (memcmp(dst_mac, my_mac, ETHER_ADDR_LEN)==0)
    { /* incoming packet */
      in=1;
      remote=src_ip;
      local=dst_ip;
      remote_mac=src_mac;
    } else if (memcmp(src_mac, my_mac, ETHER_ADDR_LEN)==0)
    { /* outgoing packet */
      in = 0;
      remote=dst_ip;
      local=src_ip;
      remote_mac=dst_mac;
    }
    else
    { /* left packet */
left:
#if 0
      if (fsnap)
      { fprintf(fsnap, "?? %02x%02x.%02x%02x.%02x%02x -> %02x%02x.%02x%02x.%02x%02x, %u.%u.%u.%u->%u.%u.%u.%u %lu bytes"
#ifndef NO_TRUNK
         " (vlan %d)"
#endif
         "\n",
         src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
         dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
         ((char *)&src_ip)[3], ((char *)&src_ip)[2], ((char *)&src_ip)[1], ((char *)&src_ip)[0],
         ((char *)&dst_ip)[3], ((char *)&dst_ip)[2], ((char *)&dst_ip)[1], ((char *)&dst_ip)[0],
         len
#ifndef NO_TRUNK
         ,vlan
#endif
        );
        fflush(fsnap);
        if ((snap_traf-=len) <= 0)
        { fclose(fsnap);
          fsnap=NULL;
          snap_traf=0;
        }
      }
#endif
      return;
    }
  } else
  { /* raw IP, no macs */
  }
  sigemptyset(&set);
  sigaddset(&set, SIGINFO);
  sigprocmask(SIG_BLOCK, &set, &oset);
  leftpacket=1;
  for (pa=attrhead; pa; pa=pa->next)
  { find=0;
    if (dst_mac)
      find=
#ifndef NO_TRUNK
        (pa->vlan==(unsigned short)-1 || pa->vlan==vlan) &&
#endif
        (pa->ip==0xfffffffful || ((pa->reverse ? local : remote) & pa->mask)==pa->ip) &&
        (pa->proto==(unsigned short)-1 || pa->proto==proto) &&
        (*(unsigned long *)pa->mac==0xfffffffful || memcmp(pa->mac, remote_mac, ETHER_ADDR_LEN)==0);
    else
    { if ((pa->ip==0xfffffffful || (src_ip & pa->mask)==pa->ip) &&
          (pa->proto==(unsigned short)-1 || pa->proto==proto))
      { find = 1;
#ifndef HAVE_PKT_TYPE
        in = 0;
#endif
      } else if ((pa->ip==0xfffffffful || (dst_ip & pa->mask)==pa->ip) &&
                 (pa->proto==(unsigned short)-1 || pa->proto==proto))
      { find = 1;
#ifndef HAVE_PKT_TYPE
        in = 1;
#endif
      }
    }
    if (find)
    {
  leftpacket=0;
  if (fsnap && !pa->fallthru)
  { 
    if (dst_mac)
      fprintf(fsnap, "%s %u.%u.%u.%u->%u.%u.%u.%u (%s.%s2%s.%s) %lu bytes ("
#ifndef NO_TRUNK
        "vlan %d, "
#endif
        "mac %02x%02x.%02x%02x.%02x%02x)\n",
        ((in^pa->reverse) ? "<-" : "->"),
        ((char *)&src_ip)[3], ((char *)&src_ip)[2], ((char *)&src_ip)[1], ((char *)&src_ip)[0],
        ((char *)&dst_ip)[3], ((char *)&dst_ip)[2], ((char *)&dst_ip)[1], ((char *)&dst_ip)[0],
        pa->link->name, uaname[find_mask(src_ip)], uaname[find_mask(dst_ip)],
        ((in^pa->reverse) ? "in" : "out"), len,
#ifndef NO_TRUNK
        vlan,
#endif
        remote_mac[0], remote_mac[1], remote_mac[2],
        remote_mac[3], remote_mac[4], remote_mac[5]);
    else
      fprintf(fsnap, 
#ifdef HAVE_PKTTYPE
                    "%s "
#endif
                    "%u.%u.%u.%u->%u.%u.%u.%u (%s.%s2%s.%s) %lu bytes\n",
#ifdef HAVE_PKTTYPE
        ((in^pa->reverse) ? "<-" : "->"),
#endif
        ((char *)&src_ip)[3], ((char *)&src_ip)[2], ((char *)&src_ip)[1], ((char *)&src_ip)[0],
        ((char *)&dst_ip)[3], ((char *)&dst_ip)[2], ((char *)&dst_ip)[1], ((char *)&dst_ip)[0],
        pa->link->name, uaname[find_mask(src_ip)], uaname[find_mask(dst_ip)],
        ((in^pa->reverse) ? "in" : "out"), len);
    fflush(fsnap);
    if ((snap_traf-=len) <= 0)
    { fclose(fsnap);
      fsnap = NULL;
      snap_traf=0;
    }
  }
  src_ua=find_mask(src_ip);
  dst_ua=find_mask(dst_ip);
  if (remote_mac && (mactable=pa->link->mactable) != NULL)
  { for (key=*(unsigned short *)(remote_mac+4) % maxmacs;
         mactable[key] && memcmp(remote_mac,mactable[key]->mac,ETHER_ADDR_LEN);
         key = (key+1) % maxmacs);
    if (mactable[key] == NULL)
    {
      mactable[key]=calloc(1, sizeof(struct mactype));
      mactable[key]->ip=malloc(sizeof(remote));
      mactable[key]->nip=1;
      mactable[key]->ip[0]=remote;
      memcpy(mactable[key]->mac, remote_mac, ETHER_ADDR_LEN);
      mactable[key]->bytes[pa->reverse^in][(in^pa->reverse) ? dst_ua : src_ua]=len;
      pa->link->nmacs++;
    }
    else
    {
      mactable[key]->bytes[pa->reverse^in][(in^pa->reverse) ? dst_ua : src_ua]+=len;
      if (mactable[key]->ip[0]!=remote)
      {
        int i;
        for (i=mactable[key]->nip-1; i>0; i--)
          if (mactable[key]->ip[i]==remote)
            break;
        if (i==0 && mactable[key]->nip++<maxcoloip)
        {
          if ((mactable[key]->nip-2)%16==0)
            mactable[key]->ip=realloc(mactable[key]->ip, (mactable[key]->nip+15)*sizeof(remote));
          mactable[key]->ip[mactable[key]->nip-1]=remote;
        }
      }
    }
  }
  if ((pa->link->bytes[in^pa->reverse][src_ua][dst_ua]+=len)>=0xf0000000lu
      || pa->link->nmacs>maxmacs/2)
    write_stat();
  if (!pa->fallthru)
    break;
    }
  }
  sigprocmask(SIG_SETMASK, &oset, NULL);
  if (leftpacket) goto left;
}

void write_stat(void)
{
  int i, j, k;
  struct linktype *pl;
  FILE *fout;

  last_write=time(NULL);
  fout = fopen(logname, "a");
  if (fout==NULL) return;
  fprintf(fout, "----- %s", ctime(&last_write));
  for (pl=linkhead; pl; pl=pl->next)
  { for (i=0; i<2; i++)
      for (j=0; j<NCLASSES; j++)
        for (k=0; k<NCLASSES; k++)
          if (pl->bytes[i][j][k])
          { 
              fprintf(fout, "%s.%s2%s.%s: %lu bytes\n",
                      pl->name, uaname[j], uaname[k], (i ? "in" : "out"),
                      pl->bytes[i][j][k]);
              pl->bytes[i][j][k]=0;
          }
    if (pl->nmacs)
    { for (k=0; k<maxmacs; k++)
        if (pl->mactable[k])
        { for (i=0; i<2; i++)
            for (j=0; j<NCLASSES; j++)
              if (pl->mactable[k]->bytes[i][j])
              { 
                fprintf(fout, "%02x%02x.%02x%02x.%02x%02x.%s.%s: %lu bytes",
                        pl->mactable[k]->mac[0], pl->mactable[k]->mac[1],
                        pl->mactable[k]->mac[2], pl->mactable[k]->mac[3],
                        pl->mactable[k]->mac[4], pl->mactable[k]->mac[5],
                        uaname[j], (i ? "in" : "out"),
                        pl->mactable[k]->bytes[i][j]);
                pl->mactable[k]->bytes[i][j]=0;
                if (pl->mactable[k]->nip)
                {
                  int nip=0;
                  fprintf(fout, " (");
                  for (nip=0; nip<pl->mactable[k]->nip; nip++)
                  { unsigned long n_remote = htonl(pl->mactable[k]->ip[nip]);
                    fprintf(fout, "%s%s",
                            inet_ntoa(*(struct in_addr *)&n_remote),
                            (nip+1==pl->mactable[k]->nip ? ")\n" : ", "));
                  }
                }
              }
          free(pl->mactable[k]->ip);
          free(pl->mactable[k]);
          pl->mactable[k] = NULL;
        }
      pl->nmacs = 0;
    }
  }
  fputs("\n", fout);
  fclose(fout);
}
