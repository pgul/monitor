
# TRUNK=-DNO_TRUNK
PCAP=-I /usr/include/pcap		# Linux RedHat
# DEFS=-DHAVE_NET_IF_VLAN_VAR_H		# BSD

COPT=-Wall -O3 -m486 -funsigned-char $(PCAP) $(TRUNK) $(DEFS)

all:	monitor

monitor:	monitor.o acl.o stat.o config.o getclass.o
	gcc $(COPT) -o monitor monitor.o acl.o stat.o config.o getclass.o -lpcap
monitor.o:	monitor.c monitor.h
	gcc $(COPT) -o monitor.o -c monitor.c
acl.o:		acl.c monitor.h
	gcc $(COPT) -o acl.o -c acl.c
stat.o:		stat.c monitor.h
	gcc $(COPT) -o stat.o -c stat.c
config.o:	config.c monitor.h
	gcc $(COPT) -o config.o -c config.c
getclass.o:	getclass.c monitor.h
	gcc $(COPT) -o getclass.o -c getclass.c

testacl:	acl.c monitor.h
	gcc -g -Wall -DDEBUG=1 -o testacl -O2 -funsigned-char acl.c
test:		test.c
	gcc -g -Wall -o test -O2 -funsigned-char test.c -lpcap
