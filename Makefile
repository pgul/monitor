
COPT=-g -Wall -O2 -funsigned-char

all:	monitor

monitor:	monitor.o acl.o stat.o
	gcc $(COPT) -o monitor monitor.o acl.o stat.o -lpcap
monitor.o:	monitor.c monitor.h
	gcc $(COPT) -o monitor.o -c monitor.c
acl.o:		acl.c monitor.h
	gcc $(COPT) -o acl.o -c acl.c
stat.o:		stat.c monitor.h
	gcc $(COPT) -o stat.o -c stat.c

testacl:	acl.c monitor.h
	gcc -g -Wall -DDEBUG=1 -o testacl -O2 -funsigned-char acl.c
test:		test.c
	gcc -g -Wall -o test -O2 -funsigned-char test.c -lpcap
