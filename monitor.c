#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <syslog.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef WITH_PORTS
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif
#include <sys/socket.h>
#include <arpa/inet.h>
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
#define DLT_LINUX_SLL	113	/* Linux cooked sockets */

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
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif
#ifdef NEED_PCAP_OPEN_LIVE_NEW_PROTO
pcap_t	*pcap_open_live_new(char *, int, int, int, char *, int, int, char *);
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

#ifdef	DLT_LINUX_SLL
#ifndef	SLL_HDR_LEN
#define SLL_HDR_LEN     16
#endif
#ifndef	SLL_ADDRLEN
#define SLL_ADDRLEN     8
#endif
struct sll_header {
	u_int16_t	sll_pkttype;	/* packet type */
	u_int16_t	sll_hatype;	/* link-layer address type */
	u_int16_t	sll_halen;	/* link-layer address length */
	u_int8_t	sll_addr[SLL_ADDRLEN];	/* link-layer address */
	u_int16_t	sll_protocol;	/* protocol */
};
#endif

int  preproc;
time_t last_write, last_reload;
long snap_traf;
FILE *fsnap, *origerr;
pcap_t *pk;
char *saved_argv[20];
char *confname;
int  linktype;
#ifdef HAVE_PCAP_OPEN_LIVE_NEW
int  real_linktype;
#endif
static char *dlt[] = {
 "null", "ethernet", "eth3m", "ax25", "pronet", "chaos",
 "ieee802", "arcnet", "slip", "ppp", "fddi", "llc/snap atm", "raw ip",
 "bsd/os slip", "bsd/os ppp", "lane 802.3", "atm" };
static unsigned char nullmac[ETHER_ADDR_LEN] = {0, 0, 0, 0, 0, 0};

void hup(int signo)
{
  /* fprintf(origerr, "Received signal %d\n", signo); */
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
    { fprintf(origerr, "Config error!\n");
      exit(1);
    }
  if (signo==SIGINFO)
  { /* snap 10M of traffic */
    int wassnap=1;
    if (fsnap) fclose(fsnap);
    else wassnap=0;
    snap_traf=10*1024*1024; 
    fsnap=fopen(snapfile, "a");
    if (fsnap==NULL)
    { snap_traf=0;
      fprintf(origerr, "Can't open %s: %s!\n", snapfile, strerror(errno));
    }
    else if (!wassnap)
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

static void switchsignals(int how)
{
  sigset_t sigset;

  /* block signals */
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGHUP);
  sigaddset(&sigset, SIGTERM);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGUSR1);
  sigaddset(&sigset, SIGUSR2);
  sigaddset(&sigset, SIGINFO);
  sigprocmask(how, &sigset, NULL);
}

void dopkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
  struct ether_header *eth_hdr;
  struct ip *ip_hdr;
  u_char *src_mac, *dst_mac;
#ifndef NO_TRUNK
  struct ether_vlan_header *vlan_hdr;
  int vlan;
#endif
#ifdef DLT_LINUX_SLL
  struct sll_header *sll_hdr;
#endif
  int in=-1;
#ifdef WITH_PORTS
  u_short src_port, dst_port;
#endif

  switchsignals(SIG_BLOCK);
#ifdef HAVE_PKT_TYPE
  if (hdr->pkt_type == 4) // PACKET_OUTGOING
    in = 0;
  else if (hdr->pkt_type == 0) // PACKET_HOST
    in = 1;
  // PACKET_BROADCAST, PACKET_MULTICAST, PACKET_OTHERHOST - use unknown
#endif
  // fprintf(origerr, "#"); fflush(origerr);
  if (linktype == DLT_EN10MB)
  {
    if (hdr->len < sizeof(*eth_hdr)+sizeof(*ip_hdr))
      goto dopkt_end;
    eth_hdr = (struct ether_header *)data;
#ifndef NO_TRUNK
    vlan=0;
    if (ntohs(eth_hdr->ether_type)==ETHERTYPE_VLAN)
    {
      vlan_hdr=(struct ether_vlan_header *)data;
      vlan=ntohs(vlan_hdr->evl_tag);
      if (ntohs(vlan_hdr->evl_proto)!=ETHERTYPE_IP)
        goto dopkt_end;
      ip_hdr = (struct ip *)(vlan_hdr+1);
    }
    else
#endif
    if (ntohs(eth_hdr->ether_type)==ETHERTYPE_IP)
      ip_hdr = (struct ip *)(eth_hdr+1);
    else
      goto dopkt_end;
  } else if (linktype == DLT_RAW)
  { 
    if (hdr->len < sizeof(*ip_hdr))
      goto dopkt_end;
    eth_hdr = NULL;
#ifndef NO_TRUNK
    vlan = 0;
#endif
    ip_hdr = (struct ip *)data;
#ifdef DLT_LINUX_SLL
  } else if (linktype == DLT_LINUX_SLL)
  { 
    if (hdr->len < sizeof(*sll_hdr)+sizeof(*ip_hdr))
      goto dopkt_end;
    sll_hdr = (struct sll_header *)data;
    eth_hdr = NULL;
#ifndef NO_TRUNK
    vlan = 0;
#endif
    if (ntohs(sll_hdr->sll_protocol)==ETHERTYPE_IP)
      ip_hdr = (struct ip *)(sll_hdr+1);
    else
      goto dopkt_end;
    if (sll_hdr->sll_pkttype == 0)	// LINUX_SLL_HOST
      in = 1;
    else if (ntohs(sll_hdr->sll_pkttype) == 4)	// LINUX_SLL_OUTGOING
      in = 0;
#endif
  } else
    goto dopkt_end;
#ifdef HAVE_PCAP_OPEN_LIVE_NEW
  if (real_linktype != DLT_EN10MB)
    src_mac = dst_mac = NULL;
  else
#endif
  if (eth_hdr)
  { src_mac = (u_char *)&eth_hdr->ether_shost;
    dst_mac = (u_char *)&eth_hdr->ether_dhost;
  } else
    src_mac = dst_mac = NULL;
#ifdef WITH_PORTS
  if (ip_hdr->ip_p == IPPROTO_TCP)
  { struct tcphdr *tcphdr = (struct tcphdr *)(ip_hdr+1);
    src_port = ntohs(tcphdr->th_sport);
    dst_port = ntohs(tcphdr->th_dport);
  } else if (ip_hdr->ip_p == IPPROTO_UDP)
  { struct udphdr *udphdr = (struct udphdr *)(ip_hdr+1);
    src_port = ntohs(udphdr->uh_sport);
    dst_port = ntohs(udphdr->uh_dport);
  } else
    src_port = dst_port = 0;
#endif
  add_stat(src_mac, dst_mac,
           *(u_long *)&(ip_hdr->ip_src), *(u_long *)&(ip_hdr->ip_dst),
           hdr->len-(eth_hdr ? ((char *)ip_hdr - (char *)eth_hdr) : 0),
#ifndef NO_TRUNK
           vlan,
#endif
           in, ip_hdr->ip_p
#ifdef WITH_PORTS
           , src_port, dst_port
#endif
           );
  if (last_write+write_interval<=time(NULL))
    write_stat();
  if (last_reload+reload_interval<=time(NULL))
    reload_acl();
dopkt_end:
  switchsignals(SIG_UNBLOCK);
}

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose)
{
  int i;
  if (!nochdir) chdir("/");
  if (!noclose)
  {
    i=open("/dev/null", O_RDONLY);
    if (i!=-1)
    { if (i>0) dup2(i, 0);
      close(i);
    }
    i=open("/dev/null", O_WRONLY);
    if (i!=-1)
    { if (i>1) dup2(i, 1);
      if (i>2) dup2(i, 2);
      close(i);
    }
  }
  if ((i=fork()) == -1) return -1;
  if (i>0) exit(0);
  setsid();
  return 0;
}
#endif

int usage(void)
{
  printf("IP traffic monitoring      " __DATE__ "\n");
  printf("    Usage:\n");
  printf("monitor [-d] [-E] [config]\n");
  printf("  -d  - daemonize\n");
  printf("  -E  - dump preprocessed config and exit\n");
  return 0;
}

#if defined(HAVE_GETIFADDRS)
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <net/if_types.h>
static int get_mac(const char *iface, unsigned char *mac)
{
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_dl *sa;
  int rc=-1;

  if (getifaddrs(&ifap))
    return -1;
  for (ifa=ifap; ifa; ifa=ifa->ifa_next) {
    if (ifa->ifa_addr->sa_family != AF_LINK) continue;
    if (strcmp(ifa->ifa_name, iface)) continue;
    sa = (struct sockaddr_dl *)ifa->ifa_addr;
    if (sa->sdl_type == IFT_ETHER) {
      memcpy(mac, sa->sdl_data+sa->sdl_nlen, 6);
      rc=0;
    }
    break;
  }
  freeifaddrs(ifap);
  return rc;
}
#elif defined(SIOCGIFHWADDR)
static int get_mac(const char *iface, unsigned char *mac)
{
  struct ifreq ifr;
  int fd = socket(PF_INET, SOCK_DGRAM, 0);
  if (fd >= 0)
  {
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, iface);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0 &&
        ifr.ifr_hwaddr.sa_family == 1 /* ARPHRD_ETHER */)
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(fd);
  }
  return 0;
}
#else
#define get_mac(iface, mac)	0
#endif

int main(int argc, char *argv[])
{
  char ebuf[PCAP_ERRBUF_SIZE]="";
  int i, daemonize;
  FILE *f;
  char *piface;

  for (i=0; i<=argc && i<sizeof(saved_argv)/sizeof(saved_argv[0]); i++)
    saved_argv[i]=argv[i];
  confname=CONFNAME;
  daemonize=0;
  while ((i=getopt(argc, argv, "dhE?")) != -1)
  {
    switch (i)
    {
      case 'd': daemonize=1; break;
      case 'E': preproc=1;   break;
      case 'h':
      case '?': usage(); return 1;
      default:  fprintf(stderr, "Unknown option -%c\n", (char)i);
		usage(); return 2;
    }
  }
  if (argc>optind)
    confname=argv[optind];

  fflush(stderr);
  i = dup(fileno(stderr));
  if (i!=-1)
  { if ((origerr=fdopen(i, "w")) == NULL)
      close(i);
  } else
    origerr=NULL;
  if (origerr)
  { f = fopen("/dev/null", "w");
    if (f)
    { dup2(fileno(f), fileno(stderr));
      fclose(f);
    }
  } else
    origerr = stderr;
  if (config(confname))
  { fprintf(origerr, "Config error\n");
    return 1;
  }
  if (preproc)
    return 0;
  if (daemonize)
    daemon(0, 0);
  if (strcmp(iface, "all") == 0)
    piface = NULL;
  else
    piface = iface;
  pk = pcap_open_live(piface, MTU, 1, 0, ebuf);
#ifdef HAVE_PCAP_OPEN_LIVE_NEW
  if (pk)
  { real_linktype = pcap_datalink(pk);
    if (real_linktype != DLT_EN10MB)
    { pcap_close(pk);
      pk = NULL;
    }
  }
  if (pk==NULL)
    pk = pcap_open_live_new(piface, MTU, -1, 0, ebuf, 0, 0, NULL);
#endif
  if (pk)
  {
    last_write=time(NULL);
    switchsignals(SIG_BLOCK);
    signal(SIGHUP, hup);
    signal(SIGUSR1, hup);
    signal(SIGUSR2, hup);
    signal(SIGINT, hup);
    signal(SIGTERM, hup);
    signal(SIGINFO, hup);
    if (reload_acl())
      fprintf(origerr, "reload acl error!\n");
    else
    { f=fopen(pidfile, "w");
      if (f)
      { fprintf(f, "%u\n", (unsigned)getpid());
        fclose(f);
      }
      linktype = pcap_datalink(pk);
      if (linktype != DLT_EN10MB && linktype != DLT_RAW
#ifdef DLT_LINUX_SLL
          && linktype != DLT_LINUX_SLL
#endif
         )
      { char *sdlt, unspec[32];
        if (linktype>0 && linktype<sizeof(dlt)/sizeof(dlt[0]))
          sdlt = dlt[linktype];
        else
        { sprintf(unspec, "unspec (%d)", linktype);
          sdlt = unspec;
        }
        fprintf(origerr, "Unsupported link type %s!\n", sdlt);
      }
      else
      {
        struct bpf_program fcode;
        bpf_u_int32 localnet, netmask;
#ifdef HAVE_PCAP_OPEN_LIVE_NEW
        if (real_linktype == DLT_EN10MB
#else
        if (linktype == DLT_EN10MB
#endif
            && memcmp(my_mac, nullmac, ETHER_ADDR_LEN)==0)
	  get_mac(iface, my_mac);
        if (pcap_lookupnet(iface, &localnet, &netmask, ebuf))
        { fprintf(origerr, "pcap_lookupnet error: %s\n", ebuf);
          netmask = localnet = 0;
        }
        if (pcap_compile(pk, &fcode, NULL, 1, netmask) == 0)
          pcap_setfilter(pk, &fcode);
// fprintf(origerr, "localnet %s, ", inet_ntoa(*(struct in_addr *)&localnet));
// fprintf(origerr, "netmask %s\n", inet_ntoa(*(struct in_addr *)&netmask));
        pcap_loop(pk, -1, dopkt, ebuf);
        fprintf(origerr, "pcap_loop error: %s\n", ebuf);
      }
      unlink(pidfile);
    }
    pcap_close(pk);
  }
  else
  { fprintf(origerr, "pcap_open_live fails: %s\n", ebuf);
  }
  return 0;
}

void warning(char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vsyslog(LOG_WARNING, format, ap);
  va_end(ap);
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

void error(char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vsyslog(LOG_ERR, format, ap);
  va_end(ap);
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}


