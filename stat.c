#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
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
#ifdef DO_PERL
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif
#endif
#include "monitor.h"

#ifndef SIGINFO
#define SIGINFO SIGIO
#endif

u_char my_mac[ETHER_ADDR_LEN]={MYMAC};
extern long snap_traf;
extern FILE *fsnap, *origerr;

void add_stat(u_char *src_mac, u_char *dst_mac, u_long src_ip, u_long dst_ip,
              u_long len,
#ifndef NO_TRUNK
              int vlan,
#endif
              int in, int proto
#ifdef WITH_PORTS
	      , u_short sport, u_short dport
#endif
	      )
{
  u_long local=0, remote=0;
  u_char *remote_mac=NULL;
  int src_ua, dst_ua, key, leftpacket, find, snaped;
  struct attrtype *pa;
  sigset_t set, oset;
  struct mactype **mactable;
#ifdef WITH_PORTS
  u_short lport=0, rport=0;
#endif

  src_ip = ntohl(src_ip);
  dst_ip = ntohl(dst_ip);
  if (dst_mac)
  { if (memcmp(dst_mac, my_mac, ETHER_ADDR_LEN)==0)
    { /* incoming packet */
      in=1;
      remote=src_ip;
      local=dst_ip;
      remote_mac=src_mac;
#ifdef WITH_PORTS
      lport=sport;
      rport=dport;
#endif
    } else if (memcmp(src_mac, my_mac, ETHER_ADDR_LEN)==0)
    { /* outgoing packet */
      in = 0;
      remote=dst_ip;
      local=src_ip;
      remote_mac=dst_mac;
#ifdef WITH_PORTS
      lport=dport;
      rport=sport;
#endif
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
  snaped=0;
  for (pa=attrhead; pa; pa=pa->next)
  { find=0;
    if (dst_mac)
      find=
#ifndef NO_TRUNK
        (pa->vlan==(unsigned short)-1 || pa->vlan==vlan) &&
#endif
        (pa->ip==0xfffffffful || ((pa->reverse ? local : remote) & pa->mask)==pa->ip) &&
        (pa->proto==(unsigned short)-1 || pa->proto==proto) &&
#ifdef WITH_PORTS
        (pa->port1==(unsigned short)-1 || (pa->port1>=(pa->reverse ? lport : rport) && (pa->port2<=(pa->reverse ? lport : rport)))) &&
        (pa->lport1==(unsigned short)-1 || (pa->lport1>=(pa->reverse ? rport : lport) && (pa->lport2<=(pa->reverse ? rport : lport)))) &&
#endif
        (*(unsigned long *)pa->mac==0xfffffffful || memcmp(pa->mac, remote_mac, ETHER_ADDR_LEN)==0);
    else
    { if ((pa->ip==0xfffffffful || (src_ip & pa->mask)==pa->ip) &&
          (pa->proto==(unsigned short)-1 || pa->proto==proto))
      { find = 1;
        if (in==-1) in = 0;
      } else if ((pa->ip==0xfffffffful || (dst_ip & pa->mask)==pa->ip) &&
                 (pa->proto==(unsigned short)-1 || pa->proto==proto))
      { find = 1;
        if (in==-1) in = 1;
      }
    }
    if (find)
    {
  leftpacket=0;
  if (!pa->link && !pa->fallthru)
    break; // ignore
  if (fsnap && !snaped)
  { 
    snaped=1;
    if (dst_mac)
      fprintf(fsnap, "%s %u.%u.%u.%u->%u.%u.%u.%u (%s.%s2%s.%s) %lu bytes ("
#ifndef NO_TRUNK
        "vlan %d, "
#endif
        "mac %02x%02x.%02x%02x.%02x%02x)\n",
        ((in^pa->reverse) ? "<-" : "->"),
        ((char *)&src_ip)[3], ((char *)&src_ip)[2], ((char *)&src_ip)[1], ((char *)&src_ip)[0],
        ((char *)&dst_ip)[3], ((char *)&dst_ip)[2], ((char *)&dst_ip)[1], ((char *)&dst_ip)[0],
        pa->link->name,
        uaname[uaindex[find_mask(src_ip)]], uaname[uaindex[find_mask(dst_ip)]],
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
        pa->link->name,
        uaname[uaindex[find_mask(src_ip)]], uaname[uaindex[find_mask(dst_ip)]],
        ((in^pa->reverse) ? "in" : "out"), len);
    fflush(fsnap);
    if ((snap_traf-=len) <= 0)
    { fclose(fsnap);
      fsnap = NULL;
      snap_traf=0;
    }
  }
  src_ua=uaindex[find_mask(src_ip)];
  dst_ua=uaindex[find_mask(dst_ip)];
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

#ifdef DO_PERL
static PerlInterpreter *perl = NULL;

void boot_DynaLoader(CV *cv);

static void xs_init(void)
{
  static char *file = __FILE__;
  dXSUB_SYS;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}

void exitperl(void)
{
  if (perl)
  {
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
  }
}

int PerlStart(void)
{
  int rc;
  char *perlargs[]={"", "", NULL};

  perlargs[1] = perlfile;
  if (access(perlfile, R_OK))
  { printf("Can't read %s: %s", perlfile, strerror(errno));
    return 1;
  }
  perl = perl_alloc();
  perl_construct(perl);
  rc=perl_parse(perl, xs_init, 2, perlargs, NULL);
  if (rc)
  { printf("Can't parse %s", perlfile);
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
    return 1;
  }
  atexit(exitperl);
  return 0;
}

static void plstart(void)
{
  STRLEN n_a;

  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlstart, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

static void plstop(void)
{
  STRLEN n_a;

  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlstop, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

static void plwrite(char *user, char *src, char *dst, char *direct, int bytes)
{
  SV *svuser, *svsrc, *svdst, *svdirect, *svbytes;
  STRLEN n_a;

  dSP;
  svuser   = perl_get_sv("user",      TRUE);
  svsrc    = perl_get_sv("src",       TRUE);
  svdst    = perl_get_sv("dst",       TRUE);
  svdirect = perl_get_sv("direction", TRUE);
  svbytes  = perl_get_sv("bytes",     TRUE);
  sv_setpv(svuser,   user  );
  sv_setpv(svsrc,    src   );
  sv_setpv(svdst,    dst   );
  sv_setpv(svdirect, direct);
  sv_setiv(svbytes,  bytes );
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlwrite, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

static void plwritemac(char *mac, char *ua, char *direct, int bytes)
{
  SV *svmac, *svua, *svdirect, *svbytes;
  STRLEN n_a;

  dSP;
  svmac    = perl_get_sv("mac",       TRUE);
  svua     = perl_get_sv("ua",        TRUE);
  svdirect = perl_get_sv("direction", TRUE);
  svbytes  = perl_get_sv("bytes",     TRUE);
  sv_setpv(svmac,    mac   );
  sv_setpv(svua,     ua    );
  sv_setpv(svdirect, direct);
  sv_setiv(svbytes,  bytes );
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlwritemac, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}
#endif

#ifdef DO_MYSQL
#include <mysql.h>
#include <getopt.h>

#if !defined(MYSQL_VERSION_ID) || MYSQL_VERSION_ID<32224
#define mysql_field_count mysql_num_fields
#endif

#define create_utable							\
       "CREATE TABLE IF NOT EXISTS %s ("				\
             "user CHAR(20) NOT NULL,"					\
             "user_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,"\
             "UNIQUE (user)"						\
        ")"
#define create_table					\
       "CREATE TABLE IF NOT EXISTS %s ("		\
             "time TIMESTAMP NOT NULL,"			\
             "user_id INT UNSIGNED NOT NULL,"		\
             "src ENUM(%s) NOT NULL,"			\
             "dst ENUM(%s) NOT NULL,"			\
             "direction ENUM('in', 'out') NOT NULL,"	\
             "bytes INT UNSIGNED NOT NULL,"		\
             "INDEX (user_id),"				\
             "INDEX (time)"				\
        ")"
#define create_mtable					\
        "CREATE TABLE IF NOT EXISTS %s ("		\
             "time TIMESTAMP NOT NULL,"			\
             "mac CHAR(16) NOT NULL,"			\
             "class ENUM(%s) NOT NULL,"			\
             "direction ENUM('in', 'out') NOT NULL,"	\
             "bytes INT UNSIGNED NOT NULL,"		\
             "INDEX (mac),"				\
             "INDEX (time)"				\
        ")"
#define create_itable					\
        "CREATE TABLE IF NOT EXISTS %s ("		\
             "mac CHAR(16) NOT NULL,"			\
             "ip  CHAR(16) NOT NULL,"			\
             "UNIQUE (mac, ip)"				\
        ")"

static void mysql_err(MYSQL *conn, char *message)
{
	fprintf(origerr, "%s\n", message);
	if (conn)
		fprintf(origerr, "Error %u (%s)\n",
		        mysql_errno(conn), mysql_error(conn));
}

static MYSQL *do_connect(char *host_name, char *user_name, char *password,
           char *db_name, unsigned port_num, char *socket_name, unsigned flags)
{
	MYSQL *conn;

	conn = mysql_init(NULL);
	if (conn==NULL)
	{	mysql_err(NULL, "mysql_init() failed");
		return NULL;
	}
#if defined(MYSQL_VERSION_ID) && MYSQL_VERSION_ID >= 32200
	if (mysql_real_connect(conn, host_name, user_name, password,
	             db_name, port_num, socket_name, flags) == NULL)
	{
		mysql_err(conn, "mysql_real_connect() failed");
		return NULL;
	}
#else
	if (mysql_real_connect(conn, host_name, user_name, password,
	             port_num, socket_name, flags) == NULL)
	{
		mysql_err(conn, "mysql_real_connect() failed");
		return NULL;
	}
	if (db_name)
	{	if (mysql_select_db(conn, dbname))
		{	mysql_err(conn, "mysql_select_db() failed");
			return NULL;
		}
	}
#endif
	return conn;
}

static void do_disconnect(MYSQL *conn)
{
	if (conn) mysql_close(conn);
}

void mysql_start(void)
{
	char *myargv_[] = {"monitor", NULL };
	char **myargv=myargv_;
	int  myargc=1, c, option_index=0;
	const char *groups[] = {"client", "monitor", NULL };
	struct option long_options[] = {
		{"host",     required_argument, NULL, 'h'},
		{"user",     required_argument, NULL, 'u'},
		{"password", required_argument, NULL, 'p'},
		{"port",     required_argument, NULL, 'P'},
		{"socket",   required_argument, NULL, 'S'},
		{"table",    required_argument, NULL, 'T'},
		{"utable",   required_argument, NULL, 'U'},
		{"mtable",   required_argument, NULL, 'M'},
		{"itable",   required_argument, NULL, 'I'},
		{"db",       required_argument, NULL, 'D'},
		{0, 0, 0, 0 }
	};

	my_init();
	load_defaults("my", groups, &myargc, &myargv);
	optind = 1;
	while ((c = getopt_long(myargc, myargv, "h:p::u:P:S:T:U:D:", long_options, &option_index)) != EOF)
	{	switch (c)
		{
			case 'h':
				strncpy(mysql_host, optarg, sizeof(mysql_host));
				break;
			case 'u':
				strncpy(mysql_user, optarg, sizeof(mysql_user));
				break;
			case 'p':
				strncpy(mysql_pwd, optarg, sizeof(mysql_pwd));
				break;
			case 'P':
				mysql_port = (unsigned)atoi(optarg);
				break;
			case 'S':
				strncpy(mysql_socket, optarg, sizeof(mysql_socket));
				break;
			case 'T':
				strncpy(mysql_table, optarg, sizeof(mysql_table));
				break;
			case 'U':
				strncpy(mysql_utable, optarg, sizeof(mysql_utable));
				break;
			case 'M':
				strncpy(mysql_mtable, optarg, sizeof(mysql_mtable));
				break;
			case 'I':
				strncpy(mysql_itable, optarg, sizeof(mysql_itable));
				break;
			case 'D':
				strncpy(mysql_db, optarg, sizeof(mysql_db));
				break;
		}
	}
}
#endif

void write_stat(void)
{
  int i, j, k;
  struct linktype *pl;
  FILE *fout;
#ifdef DO_MYSQL
  MYSQL *conn = NULL;
  char table[256], mtable[256], query[1024], stamp[15];
#if NCLASSES>=256
  static
#endif
  char enums[(sizeof(uaname[0])+4)*NCLASSES];
  int  mysql_connected=0;
  int  table_created=0, utable_created=0, mtable_created=0, itable_created=0;
  struct tm *tm_now;
  char *p;
#endif

  last_write=time(NULL);
  fout=fopen(logname, "a");
  if (fout==NULL) return;
#ifdef DO_PERL
  plstart();
#endif
#ifdef DO_MYSQL
  tm_now=localtime(&last_write);
  strftime( table, sizeof( table), mysql_table,   tm_now);
  strftime(mtable, sizeof(mtable), mysql_mtable,  tm_now);
  strftime(stamp,  sizeof(stamp), "%Y%m%d%H%M%S", tm_now);
  p=enums;
  for (i=0; i<NCLASSES && i<256; i++)
  { if (p>enums)
    { strcpy(p, ", ");
      p+=2;
    }
    *p++='\'';
    strcpy(p, uaname[i]);
    p+=strlen(p);
    *p++='\'';
  }
  *p='\0';
#endif
  fprintf(fout, "----- %s", ctime(&last_write));
  for (pl=linkhead; pl; pl=pl->next)
  { for (i=0; i<2; i++)
      for (j=0; j<NCLASSES; j++)
        for (k=0; k<NCLASSES; k++)
          if (pl->bytes[i][j][k])
          { 
#ifdef DO_PERL
            plwrite(pl->name, uaname[j], uaname[k], (i ? "in" : "out"),
                    pl->bytes[i][j][k]);
#endif
#ifdef DO_MYSQL
            if (!mysql_connected)
            {
              conn = do_connect(
                  mysql_host[0] ? mysql_host : NULL,
                  mysql_user[0] ? mysql_user : NULL,
                  mysql_pwd[0] ? mysql_pwd : NULL,
                  mysql_db[0] ? mysql_db : NULL,
                  mysql_port,
                  mysql_socket[0] ? mysql_socket : NULL,
                  0);
              mysql_connected=1;
            }
            if (conn && !utable_created)
            {
              snprintf(query, sizeof(query)-1, create_utable, mysql_utable);
              if (mysql_query(conn, query) != 0)
              { mysql_err(conn, "mysql_query() failed");
                do_disconnect(conn);
                conn=NULL;
              }
              utable_created=1;
            }
            if (conn && !table_created)
            {
              snprintf(query, sizeof(query)-1, create_table, table, enums, enums);
              if (mysql_query(conn, query) != 0)
              { mysql_err(conn, "mysql_query() failed");
                do_disconnect(conn);
                conn=NULL;
              }
              table_created=1;
            }
            if (conn && !pl->user_id)
            { char *p;
              MYSQL_RES *res_set;
              MYSQL_ROW row;

              strcpy(query, "SELECT user_id FROM ");
              strcat(query, mysql_utable);
              strcat(query, " WHERE user = '");
              p=query+strlen(query);
              p+=mysql_escape_string(p, pl->name, strlen(pl->name));
              strcpy(p, "'");
              if (mysql_query(conn, query) != 0)
              { mysql_err(conn, "mysql_query() failed");
                do_disconnect(conn);
                conn=NULL;
              }
              else
              {
                res_set = mysql_store_result(conn);
                if (res_set == NULL)
                { mysql_err(conn, "mysql_store_result() failed");
                  do_disconnect(conn);
                  conn=NULL;
                }
                else
                {
                  if ((row = mysql_fetch_row(res_set)) != NULL)
                    pl->user_id = atoi(row[0]);
                  mysql_free_result(res_set);
                }
              }
              if (conn && !pl->user_id)
              { /* new user, add to table */
                strcpy(query, "INSERT ");
                strcat(query, mysql_utable);
                strcat(query, " SET user='");
                p=query+strlen(query);
                p+=mysql_escape_string(p, pl->name, strlen(pl->name));
                strcpy(p, "'");
                if (mysql_query(conn, query) != 0)
                { mysql_err(conn, "mysql_query() failed");
                  do_disconnect(conn);
                  conn=NULL;
                }
                else
                { if (mysql_query(conn, "SELECT LAST_INSERT_ID()") != 0)
                  { mysql_err(conn, "mysql_query() failed");
                    do_disconnect(conn);
                    conn=NULL;
                  }
                  else
                  {
                    res_set = mysql_store_result(conn);
                    if (res_set == NULL)
                    { mysql_err(conn, "mysql_store_result() failed");
                      do_disconnect(conn);
                      conn=NULL;
                    }
                    else
                    {
                      if ((row = mysql_fetch_row(res_set)) != NULL)
                        pl->user_id = atoi(row[0]);
                      mysql_free_result(res_set);
                    }
                  }
                }
              }
              if (conn && !pl->user_id)
              { fprintf(stderr, "internal error working with MySQL server\n");
                do_disconnect(conn);
                conn=NULL;
              }
            }
            if (conn)
            { sprintf(query,
                 "INSERT %s VALUES('%s', '%lu', '%s', '%s', '%s', '%lu')",
                 table, stamp, pl->user_id, uaname[j], uaname[k],
                 (i ? "in" : "out"), pl->bytes[i][j][k]);
              if (mysql_query(conn, query) != 0)
              { mysql_err(conn, "mysql_query() failed");
                do_disconnect(conn);
                conn=NULL;
              }
            }
#endif
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
                char mac[15];
                sprintf(mac, "%02x%02x.%02x%02x.%02x%02x",
                        pl->mactable[k]->mac[0], pl->mactable[k]->mac[1],
                        pl->mactable[k]->mac[2], pl->mactable[k]->mac[3],
                        pl->mactable[k]->mac[4], pl->mactable[k]->mac[5]);
#ifdef DO_PERL
		plwritemac(mac, uaname[j], (i ? "in" : "out"),
                           pl->mactable[k]->bytes[i][j]);
#endif
#ifdef DO_MYSQL
                if (!mysql_connected)
                {
                  conn = do_connect(
                      mysql_host[0] ? mysql_host : NULL,
                      mysql_user[0] ? mysql_user : NULL,
                      mysql_pwd[0] ? mysql_pwd : NULL,
                      mysql_db[0] ? mysql_db : NULL,
                      mysql_port,
                      mysql_socket[0] ? mysql_socket : NULL,
                      0);
                  mysql_connected=1;
                }
                if (conn && !mtable_created)
                {
                  snprintf(query, sizeof(query)-1, create_mtable, mtable,enums);
                  if (mysql_query(conn, query) != 0)
                  { mysql_err(conn, "mysql_query() failed");
                    do_disconnect(conn);
                    conn=NULL;
                  }
                  mtable_created=1;
                }
                if (conn)
                { sprintf(query,
                     "INSERT %s VALUES('%s', '%s', '%s', '%s', '%lu')",
                     mtable, stamp, mac, uaname[j],
                     (i ? "in" : "out"), pl->bytes[i][j][k]);
                  if (mysql_query(conn, query) != 0)
                  { mysql_err(conn, "mysql_query() failed");
                    do_disconnect(conn);
                    conn=NULL;
                  }
                }
#endif
                fprintf(fout, "%s.%s.%s: %lu bytes",
                        mac, uaname[j], (i ? "in" : "out"),
                        pl->mactable[k]->bytes[i][j]);
                pl->mactable[k]->bytes[i][j]=0;
                if (pl->mactable[k]->nip)
                {
                  int nip=0;
                  fprintf(fout, " (");
                  for (nip=0; nip<pl->mactable[k]->nip; nip++)
                  {
                    struct in_addr n_remote;
                    n_remote.s_addr = htonl(pl->mactable[k]->ip[nip]);
#ifdef DO_MYSQL
                    if (conn && !itable_created)
                    {
                      snprintf(query, sizeof(query)-1, create_itable, mysql_itable);
                      if (mysql_query(conn, query) != 0)
                      { mysql_err(conn, "mysql_query() failed");
                        do_disconnect(conn);
                        conn=NULL;
                      }
                      itable_created=1;
                    }
                    if (conn)
                    { sprintf(query,
                         "INSERT IGNORE %s VALUES('%s', '%s')",
                         mysql_itable, mac,
                         inet_ntoa(n_remote));
                      if (mysql_query(conn, query) != 0)
                      { mysql_err(conn, "mysql_query() failed");
                        do_disconnect(conn);
                        conn=NULL;
                      }
                    }
#endif
                    fprintf(fout, "%s%s",
                            inet_ntoa(n_remote),
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
#ifdef DO_PERL
  plstop();
#endif
#ifdef DO_MYSQL
  if (conn) do_disconnect(conn);
#endif
}
