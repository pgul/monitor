#define CONFNAME	CONFDIR "/monitor.conf"
#define IFACE		"fxp1"
#define MTU		2048
#define MYMAC		0x00,0x30,0x80,0x35,0x50,0x43
#define LOGNAME		LOGDIR "/monitor"
#define SNAPFILE	LOGDIR "/snap"
#define ACLNAME		CONFDIR "/monitor.acl"
#define PIDFILE		"/var/run/monitor.pid"
#define WRITE_INTERVAL	(60*60)
#define RELOAD_INTERVAL	(60*10)
#define NCLASSES	2
#define MAXMACS		(16*256) /* size of hash-table */
#define MAXCOLOIP	16
#define MAXPREFIX       24

#define NBITS           2
#define MAPSIZE         (1<<MAXPREFIX)/(8/NBITS)
#define MAPKEY          (*(long *)"gul@")

#ifdef ETHER_ADDR_LEN
struct mactype {
	u_long *ip;
	unsigned long bytes[2][NCLASSES];
	int nip;
	u_char mac[ETHER_ADDR_LEN];
};

struct linktype {
	char name[32];
	unsigned long bytes[2][NCLASSES][NCLASSES];
	struct linktype *next;
	struct mactype **mactable;
	int nmacs;
};

struct attrtype {
	u_long ip, mask;
	u_char mac[ETHER_ADDR_LEN];
#ifndef NO_TRUNK
	unsigned short vlan;
#endif
	struct linktype *link;
	struct attrtype *next;
	int reverse, fallthru;
	unsigned short proto;
};

extern struct attrtype *attrhead;
extern u_char my_mac[ETHER_ADDR_LEN];
#endif

extern time_t last_write, last_reload;
extern struct linktype *linkhead;
extern char iface[];
extern char logname[], snapfile[], aclname[], pidfile[];
extern int write_interval, reload_interval;
extern int maxmacs, maxcoloip, fromshmem;
extern long mapkey;

int find_mask(unsigned long addr);
int reload_acl(void);
void add_stat(u_char *src_mac, u_char *dst_mac, u_long src_ip, u_long dst_ip,
              u_long len,
#ifndef NO_TRUNK
              int vlan,
#endif
              int proto);
void write_stat(void);
int  config(char *name);
char getclass(unsigned long addr);
void init_map(void);
