#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <net/if.h>
#ifdef HAVE_NET_IF_VLAN_VAR_H
#include <net/if_vlan_var.h>
#endif
#include <pcap.h>
#include "monitor.h"

#ifndef NO_TRUNK
#ifndef HAVE_NET_IF_VLAN_VAR_H
struct ether_vlan_header {
        unsigned char  evl_dhost[ETHER_ADDR_LEN];
        unsigned char  evl_shost[ETHER_ADDR_LEN];
        unsigned short evl_encap_proto;
        unsigned short evl_tag;
        unsigned short evl_proto;
};
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100	/* IEEE 802.1Q VLAN tagging */
#endif
#endif

#ifndef SIGINFO
#define SIGINFO SIGIO
#endif

time_t last_write, last_reload;
long snap_traf;
FILE *fsnap;
pcap_t *pk;
char *saved_argv[20];
char *confname;

void hup(int signo)
{
  if (signo==SIGHUP || signo==SIGTERM || signo==SIGINT || signo==SIGUSR2)
    write_stat();
  if (signo==SIGTERM)
  { unlink(pidfile);
    exit(0);
  }
  if (signo==SIGUSR1)
    reload_acl();
  if (signo==SIGUSR2)
    if (config(confname))
    { fprintf(stderr, "Config error!\n");
      exit(1);
    }
  if (signo==SIGINFO)
  { /* snap 10M of traffic */
    if (fsnap) fclose(fsnap);
    snap_traf=10*1024*1024; 
    fsnap=fopen(snapfile, "a");
    if (fsnap==NULL) snap_traf=0;
    else
    { time_t curtime=time(NULL);
      fprintf(fsnap, "\n\n----- %s\n", ctime(&curtime));
    }
  }
  if (signo==SIGINT)
  { /* restart myself */
    pcap_close(pk);
    unlink(pidfile);
    execvp(saved_argv[0], saved_argv);
    exit(5);
  }
  signal(signo, hup);
}

void dopkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
  struct ether_header *eth_hdr;
  struct ip *ip_hdr;
#ifndef NO_TRUNK
  struct ether_vlan_header *vlan_hdr;
  int vlan;
#endif
#if 0
  if (snap_traf>0)
  {
    bpf_u_int32 len;
    for (len=0; len<hdr->len; len++)
    { fprintf(fsnap, "%02x", data[len]);
      if ((len+1)%16) fputc(' ', fsnap);
      else fputc('\n', fsnap);
    }
    if (len%16)
      fputc('\n', fsnap);
    fputc('\n', fsnap);
    snap_traf-=hdr->len;
    if (snap_traf<=0)
    { fclose(fsnap);
      fsnap=NULL;
      snap_traf=0;
    }
  }
#endif
  if (hdr->len < sizeof(*eth_hdr)+sizeof(*ip_hdr))
    return;
  eth_hdr = (struct ether_header *)data;
#ifndef NO_TRUNK
  vlan=0;
  if (ntohs(eth_hdr->ether_type)==ETHERTYPE_VLAN)
  {
    vlan_hdr=(struct ether_vlan_header *)data;
    vlan=ntohs(vlan_hdr->evl_tag);
    if (ntohs(vlan_hdr->evl_proto)!=ETHERTYPE_IP)
      return;
    ip_hdr = (struct ip *)(vlan_hdr+1);
  }
  else
#endif
  if (ntohs(eth_hdr->ether_type)==ETHERTYPE_IP)
    ip_hdr = (struct ip *)(eth_hdr+1);
  else
    return;
#if 0
  if (snap_traf>0)
  { int in;
    if (memcmp(eth_hdr->ether_shost, my_mac, ETHER_ADDR_LEN)==0)
      in=0;
    else if (memcmp(eth_hdr->ether_dhost, my_mac, ETHER_ADDR_LEN)==0)
      in=1;
    else
      in=-1;
    fprintf(fsnap, "%s %u.%u.%u.%u -> %u.%u.%u.%u %lu bytes ("
#ifndef NO_TRUNK
            "vlan %d, "
#endif
            "mac %02x%02x.%02x%02x.%02x%02x)\n",
            (in ? (in==1 ? "<-" : "??") : "->"),
            ((char *)(&(ip_hdr->ip_src)))[0],
            ((char *)(&(ip_hdr->ip_src)))[1],
            ((char *)(&(ip_hdr->ip_src)))[2],
            ((char *)(&(ip_hdr->ip_src)))[3],
            ((char *)(&(ip_hdr->ip_dst)))[0],
            ((char *)(&(ip_hdr->ip_dst)))[1],
            ((char *)(&(ip_hdr->ip_dst)))[2],
            ((char *)(&(ip_hdr->ip_dst)))[3],
            (unsigned long)hdr->len, 
#ifndef NO_TRUNK
            vlan,
#endif
            in ? eth_hdr->ether_shost[0] : eth_hdr->ether_dhost[0],
            in ? eth_hdr->ether_shost[1] : eth_hdr->ether_dhost[1],
            in ? eth_hdr->ether_shost[2] : eth_hdr->ether_dhost[2],
            in ? eth_hdr->ether_shost[3] : eth_hdr->ether_dhost[3],
            in ? eth_hdr->ether_shost[4] : eth_hdr->ether_dhost[4],
            in ? eth_hdr->ether_shost[5] : eth_hdr->ether_dhost[5]);
    if ((snap_traf-=(long)hdr->len) <= 0)
    { fclose(fsnap);
      fsnap=NULL;
      snap_traf=0;
    }
  }
#endif
  add_stat(eth_hdr->ether_shost, eth_hdr->ether_dhost,
           *(u_long *)&(ip_hdr->ip_src), *(u_long *)&(ip_hdr->ip_dst),
           hdr->len-((char *)ip_hdr - (char *)eth_hdr),
#ifndef NO_TRUNK
           vlan,
#endif
           ip_hdr->ip_p);
  if (last_write+write_interval<=time(NULL))
    write_stat();
  if (last_reload+reload_interval<=time(NULL))
    reload_acl();
}

int main(int argc, char *argv[])
{
  char ebuf[4096]="";
  int i;

  if (argc>1)
    confname=argv[1];
  else
    confname=CONFNAME;
  if (config(confname))
  { fprintf(stderr, "Config error\n");
    return 1;
  }
  pk = pcap_open_live(iface, MTU, 1, 0, ebuf);
  for (i=0; i<=argc; i++)
    saved_argv[i]=argv[i];
  if (pk)
  {
    last_write=time(NULL);
    signal(SIGHUP, hup);
    signal(SIGUSR1, hup);
    signal(SIGUSR2, hup);
    signal(SIGINT, hup);
    signal(SIGTERM, hup);
    signal(SIGINFO, hup);
    if (reload_acl())
      printf("reload acl error!\n");
    else
    { FILE *f=fopen(pidfile, "w");
      if (f)
      { fprintf(f, "%u\n", getpid());
        fclose(f);
      }
      pcap_loop(pk, -1, dopkt, NULL);
      unlink(pidfile);
    }
    pcap_close(pk);
  }
  else
  { printf("pcap_open_live fails: %s\n", ebuf);
  }
  return 0;
}
