#define IFACE		"fxp1"
#define MTU		2048
#define MYMAC		0x00,0x01,0x42,0x71,0x24,0x40
#define LOGNAME		"/var/log/netflow/monitor"
#define SNAPFILE	"/var/log/netflow/traff"
#define ACLNAME		"/home/gul/work/monitor/acl"
#define WRITE_INTERVAL	(60*60)
#define RELOAD_INTERVAL	(60*10)
#define MAXCOLOIP	10

#define ZEOS_MAC	0x00,0x02,0xb9,0xbb,0x77,0xf0

extern time_t last_write, last_reload;

int find_mask(unsigned long addr);
int reload_acl(void);
void add_stat(u_char *src_mac, u_char *dst_mac, u_long src_ip, u_long dst_ip,
              u_long len, int vlan, int proto);
void write_stat(void);
