#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <net/if.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#else
#include <netinet/if_ether.h>
#endif
#ifdef HAVE_NET_IF_VLAN_VAR_H
#include <net/if_vlan_var.h>
#endif
#if defined(HAVE_PCAP_PCAP_H)
#include <pcap/pcap.h>
#elif defined(HAVE_PCAP_H)
#include <pcap.h>
#else
#define DLT_NULL	0	/* no link-layer encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* IEEE 802 Networks */
#define DLT_ARCNET	7	/* ARCNET */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */
#define DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define DLT_RAW		12	/* raw IP */
#define DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */
#define DLT_LANE8023    15      /* LANE 802.3(Ethernet) */
#define DLT_CIP         16      /* ATM Classical IP */

typedef struct pcap pcap_t;
struct pcap_pkthdr {
	struct timeval ts;      /* time stamp */
	unsigned caplen;     /* length of portion present */
	unsigned len;        /* length this packet (off wire) */
};                                                                 
struct bpf_program {
#ifdef __linux__
	/* Thanks, Alan  8) */
	unsigned short bf_len;
#else
	unsigned int bf_len;
#endif
	struct bpf_insn *bf_insns;
};
typedef int bpf_int32;
typedef unsigned int bpf_u_int32;
typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);

pcap_t	*pcap_open_live(char *, int, int, int, char *);
void	pcap_close(pcap_t *);
int	pcap_loop(pcap_t *, int, pcap_handler, u_char *);
int	pcap_datalink(pcap_t *);
int	pcap_lookupnet(char *, bpf_u_int32 *, bpf_u_int32 *, char *);
int	pcap_compile(pcap_t *, struct bpf_program *, char *, int, bpf_u_int32);
int	pcap_setfilter(pcap_t *, struct bpf_program *);

#endif
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
int  linktype;
static char *dlt[] = {
 "null", "ethernet", "eth3m", "ax25", "pronet", "chaos",
 "ieee802", "arcnet", "slip", "ppp", "fddi", "llc/snap atm", "raw ip",
 "bsd/os slip", "bsd/os ppp", "lane 802.3", "atm" };

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
  // fprintf(stderr, "#"); fflush(stderr);
  if (linktype == DLT_EN10MB)
  {
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
  } else if (linktype == DLT_RAW)
  { 
    if (hdr->len < sizeof(*ip_hdr))
      return;
    eth_hdr = NULL;
#ifndef NO_TRUNK
    vlan = 0;
#endif
    ip_hdr = (struct ip *)data;
  } else
    return;
  add_stat(eth_hdr ? (u_char *)&eth_hdr->ether_shost : NULL,
	   eth_hdr ? (u_char *)&eth_hdr->ether_dhost : NULL,
           *(u_long *)&(ip_hdr->ip_src), *(u_long *)&(ip_hdr->ip_dst),
           hdr->len-(eth_hdr ? ((char *)ip_hdr - (char *)eth_hdr) : 0),
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
      { fprintf(f, "%u\n", (unsigned)getpid());
        fclose(f);
      }
      linktype = pcap_datalink(pk);
      if (linktype != DLT_EN10MB && linktype != DLT_RAW)
        printf("Unsupported link type %s!\n",
          (linktype>0 && linktype<sizeof(dlt)/sizeof(dlt[0])) ? dlt[linktype] : "unspec");
      else
      {
        struct bpf_program fcode;
        bpf_u_int32 localnet, netmask;
        pcap_lookupnet(iface, &localnet, &netmask, ebuf);
        if (pcap_compile(pk, &fcode, NULL, 1, netmask) == 0)
          pcap_setfilter(pk, &fcode);
        pcap_loop(pk, -1, dopkt, NULL);
      }
      unlink(pidfile);
    }
    pcap_close(pk);
  }
  else
  { printf("pcap_open_live fails: %s\n", ebuf);
  }
  return 0;
}

