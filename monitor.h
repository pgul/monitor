#define CONFNAME	CONFDIR "/monitor.conf"
#define IFACE		"all"
#define MTU		2048
#define MYMAC		0x00,0x00,0x00,0x00,0x00,0x00
#define LOGNAME		LOGDIR "/monitor"
#define SNAPFILE	LOGDIR "/snap"
#define ACLNAME		CONFDIR "/monitor.acl"
#define PIDFILE		"/var/run/monitor.pid"
#define WRITE_INTERVAL	(60*60)
#define RELOAD_INTERVAL	(60*10)
#define SNAP_TIME	60
#define MAXMACS		(16*256) /* size of hash-table */
#define MAXCOLOIP	16
#define CACHESIZE	65536
#ifndef MAXPREFIX
#define MAXPREFIX       24
#endif
#ifndef NBITS
#define NBITS           0
#endif
#define NCLASSES	(1<<NBITS)
#if NBITS>8
#define MAPSIZE         (1<<MAXPREFIX)*(NBITS/8)
#elif NBITS==0
#define MAPSIZE		0
#else
#define MAPSIZE         (1<<MAXPREFIX)/(8/NBITS)
#endif
#define MAPKEY          (*(long *)"gul@")
#if NBITS>8
typedef unsigned short classtype;
#else
typedef unsigned char classtype;
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#ifdef ETHER_ADDR_LEN
struct mactype {
	u_long *ip;
	unsigned long bytes[2][NCLASSES];
	int nip;
	u_char mac[ETHER_ADDR_LEN];
};

struct linktype {
	char name[32];
#ifdef DO_MYSQL
	unsigned long user_id;
#endif
	unsigned long bytes[2][NCLASSES][NCLASSES];
	struct linktype *next;
	struct mactype **mactable;
	int nmacs;
};

struct attrtype {
	u_long ip, mask, remote, rmask;
	u_char mac[ETHER_ADDR_LEN];
#ifndef NO_TRUNK
	unsigned short vlan;
#endif
	struct linktype *link;
	struct attrtype *next;
	int reverse, fallthru;
	unsigned short proto;
#ifdef WITH_PORTS
	unsigned short port1, port2, lport1, lport2;
#endif
};

extern struct attrtype *attrhead;
extern u_char my_mac[ETHER_ADDR_LEN];
#endif

extern time_t last_write, last_reload;
extern struct linktype *linkhead;
extern int  preproc, allmacs;
extern char iface[];
extern char logname[], snapfile[], aclname[], pidfile[];
extern int  write_interval, reload_interval;
extern int  maxmacs, maxcoloip, fromshmem;
extern long mapkey;
extern char uaname[NCLASSES][32];
extern int  uaindex[NCLASSES];

int find_mask(unsigned long addr);
int reload_acl(void);
void add_stat(u_char *src_mac, u_char *dst_mac, u_long src_ip, u_long dst_ip,
              u_long len,
#ifndef NO_TRUNK
              int vlan,
#endif
              int in, int proto
#ifdef WITH_PORTS
              , u_short sport, u_short dport
#endif
              );
void write_stat(void);
int  config(char *name);
classtype getclass(unsigned long addr);
int  init_map(void);
void freeshmem(void);
void warning(char *format, ...);
void error(char *format, ...);

#ifdef DO_PERL
int  PerlStart(char *perlfile);
void exitperl(void);
void plstart(void);
void plstop(void);
#if NBITS>0
void plwrite(char *user, char *src, char *dst, char *direct, unsigned long bytes);
void plwritemac(char *mac, char *ua, char *direct, unsigned long bytes);
#else
void plwrite(char *user, unsigned long bytes_in, unsigned long bytes_out);
void plwritemac(char *mac, unsigned long bytes_in, unsigned long bytes_out);
#endif
void perl_call(char *file, char *func, char **args);

extern char perlfile[], perlstart[], perlwrite[];
extern char perlwritemac[], perlstop[];
#else
#define plstart()
#define plstop()
#if NBITS>0
#define plwrite(user, src, dst, direct, bytes)
#define plwritemac(mac, ua, direct, bytes)
#else
#define plwrite(user, bytes_in, bytes_out)
#define plwritemac(mac, bytes_in, bytes_out)
#endif
#endif

#ifdef DO_MYSQL
extern char mysql_user[256], mysql_pwd[256], mysql_host[256];
extern char mysql_socket[256], mysql_db[256];
extern char mysql_table[256], mysql_utable[256], mysql_mtable[256];
extern char mysql_itable[256];
extern unsigned mysql_port;

void mysql_start(void);
#endif
