#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_vlan_var.h>
#include <pcap.h>
#include "monitor.h"

time_t last_write, last_reload;
static long snap_traf;
static FILE *fsnap;
extern u_char my_mac[ETHER_ADDR_LEN];
pcap_t *pk;
char *saved_argv[20];

void hup(int signo)
{
  if (signo==SIGHUP || signo==SIGTERM || signo==SIGINT)
    write_stat();
  if (signo==SIGTERM)
    exit(0);
  if (signo==SIGUSR1)
    reload_acl();
  if (signo==SIGUSR2)
  { /* snap 1M of traffic */
    if (fsnap) fclose(fsnap);
    snap_traf=1024*1024; 
    fsnap=fopen(SNAPFILE, "a");
    if (fsnap==NULL) snap_traf=0;
    else
    { time_t curtime=time(NULL);
      fprintf(fsnap, "\n\n----- %s\n", ctime(&curtime));
    }
  }
  if (signo==SIGINT)
  { /* restart myself */
    pcap_close(pk);
    execvp(saved_argv[0], saved_argv);
    exit(5);
  }
  signal(signo, hup);
}

void dopkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
  struct ether_header *eth_hdr;
  struct ether_vlan_header *vlan_hdr;
  struct ip *ip_hdr;
  int vlan;
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
  vlan=0;
  if (ntohs(eth_hdr->ether_type)==ETHERTYPE_VLAN)
  {
    vlan_hdr=(struct ether_vlan_header *)data;
    vlan=ntohs(vlan_hdr->evl_tag);
    if (ntohs(vlan_hdr->evl_proto)!=ETHERTYPE_IP)
      return;
    ip_hdr = (struct ip *)(vlan_hdr+1);
  }
  else if (ntohs(eth_hdr->ether_type)==ETHERTYPE_IP)
    ip_hdr = (struct ip *)(eth_hdr+1);
  else
    return;
#if 1
  if (snap_traf>0)
  { int in;
    if (memcmp(eth_hdr->ether_shost, my_mac, ETHER_ADDR_LEN)==0)
      in=0;
    else if (memcmp(eth_hdr->ether_dhost, my_mac, ETHER_ADDR_LEN)==0)
      in=1;
    else
      in=-1;
    fprintf(fsnap, "%s %u.%u.%u.%u -> %u.%u.%u.%u %lu bytes (vlan %d)\n",
            (in ? (in==1 ? "<-" : "??") : "->"),
            ((char *)(&(ip_hdr->ip_src)))[0],
            ((char *)(&(ip_hdr->ip_src)))[1],
            ((char *)(&(ip_hdr->ip_src)))[2],
            ((char *)(&(ip_hdr->ip_src)))[3],
            ((char *)(&(ip_hdr->ip_dst)))[0],
            ((char *)(&(ip_hdr->ip_dst)))[1],
            ((char *)(&(ip_hdr->ip_dst)))[2],
            ((char *)(&(ip_hdr->ip_dst)))[3],
            (unsigned long)hdr->len, vlan);
    if ((snap_traf-=(long)hdr->len) <= 0)
    { fclose(fsnap);
      fsnap=NULL;
      snap_traf=0;
    }
  }
#endif
  add_stat(eth_hdr->ether_shost, eth_hdr->ether_dhost,
           *(u_long *)&(ip_hdr->ip_src), *(u_long *)&(ip_hdr->ip_dst),
           hdr->len-((char *)ip_hdr - (char *)eth_hdr), vlan,
           ip_hdr->ip_p);
  if (last_write+WRITE_INTERVAL<=time(NULL))
    write_stat();
  if (last_reload+RELOAD_INTERVAL<=time(NULL))
    reload_acl();
}

int main(int argc, char *argv[])
{
  char ebuf[4096]="";
  int i;

  pk = pcap_open_live(IFACE, MTU, 1, 0, ebuf);
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
    if (reload_acl())
      printf("reload acl error!\n");
    else
      pcap_loop(pk, -1, dopkt, NULL);
    pcap_close(pk);
  }
  else
  { printf("pcap_open_live fails: %s\n", ebuf);
  }
  return 0;
}
