#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "monitor.h"

#define NVLANS	11
#define NLINKS	(sizeof(linkname)/sizeof(linkname[0]))

struct colostat {
	u_long *ip;
	unsigned long bytes[2][3];
	int nip;
	u_char mac[ETHER_ADDR_LEN];
};
u_char my_mac[ETHER_ADDR_LEN]={MYMAC};
u_char zeos_mac[ETHER_ADDR_LEN]={ZEOS_MAC};
u_char wnet_mac[ETHER_ADDR_LEN]={WNET_MAC};
static struct colostat *mactable[256*16], *macarr[256*8];
static int nmac;
static char *linkname[]={
	"tsystems",
	"unis",
	"ukrnet",
	"impuls",
	"navigator",
	"incosoft",
	"merezha",
	"merlin",
	"ua-ix",
	"adamant",
	"gipek",
	/* and links without leased vlan */
	"zeos",
	"cssuz",
	"ugpp",
	"merezha-icmp", 
	"wmnet" };
static unsigned long bytes_link[NLINKS][2][3][3];
static unsigned long bytes_local[2][3], bytes_colo[2][3];
static unsigned long bytes_dialup[2][3], bytes_apollo[2][3];
static int uplinks[]={2, 1, 1, 2, 1, 0, 2, 0, 1, 2, 0, 1, 0, 0};
static char *uaname[3]={"world","ua","local"};


void add_stat(u_char *src_mac, u_char *dst_mac, u_long src_ip, u_long dst_ip,
              u_long len, int vlan, int proto)
{
  u_long local, remote, *counter;
  u_char *remote_mac;
  unsigned short key;
  int i, in, ua, src_ua, dst_ua, strange;
  src_ip = ntohl(src_ip);
  dst_ip = ntohl(dst_ip);
  if (memcmp(dst_mac, my_mac, ETHER_ADDR_LEN)==0)
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
    /* left packet */
    return;
  strange=0;
  if (vlan==3) /* colocation */
  {
    ua=find_mask(local);
    if ((remote & 0xffffff00) != 0x3e950000)
      strange=1;
    counter=&(bytes_colo[in][ua]);
findmac:
    for (key=*(unsigned short *)(remote_mac+4) & 0xfff;
         mactable[key] && memcmp(remote_mac,mactable[key]->mac,ETHER_ADDR_LEN);
         key = (key+1)&0xfff);
    if (mactable[key]==NULL)
    {
	if (nmac++>=256*8)
	{	write_stat();
		goto findmac;
	}
	macarr[nmac-1]=mactable[key]=calloc(1, sizeof(struct colostat));
        mactable[key]->ip=malloc(sizeof(remote));
	mactable[key]->nip=1;
	mactable[key]->ip[0]=remote;
	memcpy(mactable[key]->mac, remote_mac, ETHER_ADDR_LEN);
	mactable[key]->bytes[in][ua]=len;
    }
    else
    {
	if (mactable[key]->ip[0]!=remote)
	{
		i=mactable[key]->nip-1;
		if (i>=MAXCOLOIP) i=MAXCOLOIP-1;
		for (i=mactable[key]->nip-1; i>0; i--)
			if (mactable[key]->ip[i]==remote)
				break;
		if (i==0 && mactable[key]->nip++<MAXCOLOIP)
		{
			if ((mactable[key]->nip-2)%16==0)
				mactable[key]->ip=realloc(mactable[key]->ip, (mactable[key]->nip+15)*sizeof(remote));
			mactable[key]->ip[mactable[key]->nip-1]=remote;
		}
	}
	mactable[key]->bytes[in][ua]+=len;
    }
  }
  else if (vlan>=200 && vlan<200+NVLANS) /* external links */
  {	src_ua = find_mask(src_ip);
        dst_ua = find_mask(dst_ip);
	i=vlan-200;
	if (vlan==209 && memcmp(remote_mac, zeos_mac, ETHER_ADDR_LEN)==0)
	// if (vlan==209 && ((remote & 0xffffff00) == 0xc2998000 || remote == 0x3e950256))
		i=NVLANS; /* zeos */
	if (vlan==206 && proto==IPPROTO_ICMP)
		i=NVLANS+3; /* merezha-icmp */
	// if (vlan==200 && ((remote & 0xfffff000) == 0xd914a000 || remote == 0x3e950272))
	if (vlan==200 && memcmp(remote_mac, wnet_mac, ETHER_ADDR_LEN) == 0)
		i=NVLANS+4; /* wnet */
	counter=&(bytes_link[i][in][src_ua][dst_ua]);
	if (uplinks[i]==2 && ((in ? dst_ua : src_ua) == 0))
		strange=1;
	else if (uplinks[i]==1 && (src_ua==0 || dst_ua==0))
		strange=1;
	else if (uplinks[i]==0 && ((in ? src_ua : dst_ua) == 0))
		strange=1;
  }
  else if (vlan==4 &&
           ((remote == 0x3e95025a) || ((remote & 0xffffff00) == 0x3e950500)))
  { /* cssuz */
    counter=&(bytes_link[NVLANS+1][in][in ? 3 : find_mask(src_ip)][in ? find_mask(dst_ip) : 3]);
  }
  else if (vlan==4 &&
           ((remote & 0xffffff00) == 0x3e950600))
  { /* ugpp */
    counter=&(bytes_link[NVLANS+2][in][in ? 3 : find_mask(src_ip)][in ? find_mask(dst_ip) : 3]);
  }

  else if (remote == 0x3e950204)
  { /* apollo */
    ua = find_mask(local);
    counter=&(bytes_apollo[in][ua]);
  }
  else
  { /* local */
    ua = find_mask(local);
    counter=&bytes_local[in][ua];
  }
  *counter+=len;
  if (*counter>=0xf0000000lu)
    write_stat();
#if 0
  if (strange)
    fprintf(stderr, "%s %u.%u.%u.%u -> %u.%u.%u.%u %lu bytes (vlan %u): %s to %s\n",
         (in ? (in==1 ? "<-" : "??") : "->"),
         ((char *)(&(src_ip)))[3],
         ((char *)(&(src_ip)))[2],
         ((char *)(&(src_ip)))[1],
         ((char *)(&(src_ip)))[0],
         ((char *)(&(dst_ip)))[3],
         ((char *)(&(dst_ip)))[2],
         ((char *)(&(dst_ip)))[1],
         ((char *)(&(dst_ip)))[0],
         len, vlan, uaname[find_mask(src_ip)], uaname[find_mask(dst_ip)]);
#endif
  if ((local & 0xffffff00) == 0x3e950100)
  {
    ua = find_mask(remote);
    bytes_dialup[in ? 0 : 1][ua]+=len;
  }
#if 0
  else if (local & 0xfffff000 == 0xd90cc000)
  { /* ITL */
    ...
  }
#endif
}

void write_stat(void)
{
  int i, j, k, link;
  FILE *fout;

  last_write=time(NULL);
  fout = fopen(LOGNAME, "a");
  if (fout==NULL) return;
  fprintf(fout, "----- %s", ctime(&last_write));
  for (link=0; link<NLINKS; link++)
    for (i=0; i<2; i++)
      for (j=0; j<3; j++)
        for (k=0; k<3; k++)
          if (bytes_link[link][i][j][k])
          { 
              fprintf(fout, "%s.%s2%s.%s: %lu bytes\n",
                      linkname[link], uaname[j], uaname[k], i ? "in" : "out",
                      bytes_link[link][i][j][k]);
              bytes_link[link][i][j][k]=0;
          }
  for(i=0; i<2; i++)
    for (j=0; j<3; j++)
      if (bytes_local[i][j])
      { fprintf(fout, "local.%s.%s: %lu bytes\n",
                i ? "in" : "out", uaname[j], bytes_local[i][j]);
        bytes_local[i][j]=0;
      }
  for(i=0; i<2; i++)
    for (j=0; j<3; j++)
      if (bytes_colo[i][j])
      { fprintf(fout, "colo.%s.%s: %lu bytes\n",
                i ? "in" : "out", uaname[j], bytes_colo[i][j]);
        bytes_colo[i][j]=0;
      }
  for(i=0; i<2; i++)
    for (j=0; j<3; j++)
      if (bytes_apollo[i][j])
      { fprintf(fout, "apollo.%s.%s: %lu bytes\n",
                i ? "in" : "out", uaname[j], bytes_apollo[i][j]);
        bytes_apollo[i][j]=0;
      }
  for(i=0; i<2; i++)
    for (j=0; j<3; j++)
      if (bytes_dialup[i][j])
      { fprintf(fout, "dialup.%s.%s: %lu bytes\n",
                i ? "in" : "out", uaname[j], bytes_dialup[i][j]);
        bytes_dialup[i][j]=0;
      }

  for (i=0; i<nmac; i++)
  { for (j=0; j<2; j++)
      for (k=0; k<3; k++)
        if (macarr[i]->bytes[j][k])
        {
          fprintf(fout, "%02x%02x.%02x%02x.%02x%02x.%s.%s: %lu bytes (",
                  macarr[i]->mac[0],
                  macarr[i]->mac[1],
                  macarr[i]->mac[2],
                  macarr[i]->mac[3],
                  macarr[i]->mac[4],
                  macarr[i]->mac[5],
                  uaname[k], j ? "in" : "out",
                  macarr[i]->bytes[j][k]);
          for (link=0; link<macarr[i]->nip && link<MAXCOLOIP; link++)
          { u_long ip = htonl(macarr[i]->ip[link]);
            fprintf(fout, "%s%s", link ? ", " : "",
                    inet_ntoa(*(struct in_addr *)&ip));
          }
          if (macarr[i]->nip>MAXCOLOIP)
            fprintf(fout, ", ... - %u addresses", macarr[i]->nip);
          fprintf(fout, ")\n");
        }
    free(macarr[i]->ip);
    free(macarr[i]);
  }
  nmac=0;
  memset(mactable, 0, sizeof(mactable));

  fclose(fout);
}
