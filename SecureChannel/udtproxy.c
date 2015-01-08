/*
 ============================================================================
 Name        : udtproxy.c
 Author      : Rysavy&Rab; {rysavy,rabj}@fit.vutbr.cz
 Date        : Feb 26, 2009
 Copyright   : (c) Brno University of Technology
 Description : A proxy that injects unreliability to UDP data communication.

 This proxy can emulate packet drop, reordering and transmission error.
 Bit-error in packet content is set by -R option, where argument determines
 the ratio of incorrect packets to all processed packets.
 Packet reordering and packet loose can be modeled by setting queue size -Q (in packets),
 mean packet delay -D (in ms) and jitter -J (in ms).

 The actual delay of a single packet is computed
 as DP = D + (Random % (J * 2) ) - J, i.e. it is always in the range (D-J, D+J).

 Example:
 udtproxy -Q 10 -D 10 -J 5 -R 10 -a 10000 -A 20000 -b 30000 -B 40000


   |-------| 10000            30000 |--------|
   | Alice |<---------|    |------->| Bob    |
   |-------|          |    |        |--------|
      |               |    |             |
      |             |---------|          |
      |             | UDTProxy|          |
      |------------>|---------|<---------|
                20000        40000

 Ports are specified using -a, -A, -b, and -B options. Options -a and -b denote
 remote ports to which proxy delivers data.
 Options -A and -B denote local ports on which proxy listens.




 Usage:
 udtproxy -Q queue-len -D mean-delay -J jitter -R error-ratio
          -a remote-port-alice -A local-port-alice
          -b remote-port-bob   -B local-port-bob
          -l address-alice     -o address-bob

 Note -l and -o arguments must be a valid ip address. The use of domain names
 instead of ip addresses is not supported.

 Port numbers are mandatory arguments, other are optional and their
 default values are:
 queue-len = 10
 mean-delay = 0
 jitter = 0
 error-ration = 0
 address-alice = 127.0.0.1
 address-bob = 127.0.0.1
 ============================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include "udt.h"
#include <sys/time.h>
#include <signal.h>
#define PROGRAM "udtproxy"
#define PROGRAM_INFO "UDT Proxy with unreliability injection, version 1.0 (Feb 27, 2009)\n\n"
#define MAXLINE 500
#define IN_ADDR_LOCALHOST  0x7f000001

in_port_t remote_alice_port = 0;
in_port_t local_alice_port = 0;
in_port_t remote_bob_port = 0;
in_port_t local_bob_port = 0;
in_addr_t addr_alice = IN_ADDR_LOCALHOST;
in_addr_t addr_bob = IN_ADDR_LOCALHOST;

int queue_size = 10;
int delay = 0;
int jitter = 0;
int biterror_rate = 0;
int packets_dropped = 0;
int packets_received = 0;
int packets_sent = 0;
int packets_modified = 0;
int udt_alice = 0;
int udt_bob = 0;
int debug_level = 0;


void debug(int level, char *fmt, ...) {
   va_list argptr;
   va_start(argptr, fmt);

	if (debug_level >= level) {
		fprintf(stderr, "DEBUG: ");
		vfprintf(stderr, fmt, argptr);
	}
}

struct BufferPool {
	int timeout;
 	void *data;
	size_t datalen;
};

struct BufferPool * buffer_bob;
struct BufferPool * buffer_alice;

struct BufferPool * find_empty_slot(struct BufferPool* start, int num) {
	int i = 0;
	for(i = 0; i < num; i++) {
		if (start[i].timeout == 0 && start[i].data == NULL && start[i].datalen ==0)
			return &(start[i]);
	}
	return NULL;
}
int determine_delay(int delay, int jitter) {
	int rjit = (jitter!=0) ? random() % (jitter  * 2) : 0;
	int res = delay + (rjit - jitter);
	return res;
}

void * memdup(void *src, size_t len) {
	void *dst = malloc(len);
	return memcpy(dst, src, len);
}
// Called when Ctrl+C pressed. Just print out statistics and close the program.
void sigint_handler(int sig) {
	fprintf(stdout, "\n--- Statistics ---\n");
	float ratio = (packets_dropped > 0) ? ((float)(packets_dropped))/(packets_received) : .0;
	fprintf(stdout, "%d packets transmitted, %d packets dropped, %.1f%% packet loss\n", packets_sent, packets_dropped, ratio*100);
	float ratio2 = (packets_modified > 0) ? ((float)(packets_modified))/packets_received : .0;
	fprintf(stdout, "%d packets received, %d packets modified, %.1f%% packet errors\n", packets_received, packets_modified, ratio2*100);
	fprintf(stdout, "Quit.\n");
	exit(EXIT_SUCCESS);
}
void sigalrm_handler(int sig) {
	int i;
	for(i = 0; i < queue_size; i++) {
		if (buffer_bob[i].timeout>0)
			buffer_bob[i].timeout--;
		if (buffer_alice[i].timeout>0)
			buffer_alice[i].timeout--;

		if (buffer_bob[i].timeout==0 && buffer_bob[i].data != NULL) {
			udt_send(udt_alice,addr_alice,remote_alice_port, buffer_bob[i].data, buffer_bob[i].datalen);
			packets_sent++;
			debug(1,  "Send packet to Alice from Bob's Buffer[%d].\n", i);
			free(buffer_bob[i].data);
			buffer_bob[i].data = NULL;
			buffer_bob[i].datalen = 0;
		}
		if (buffer_alice[i].timeout==0 && buffer_alice[i].data != NULL) {
			udt_send(udt_bob, addr_bob, remote_bob_port, buffer_alice[i].data, buffer_alice[i].datalen);
			packets_sent++;
			debug(1,  "Send packet to Bob from Alice's Buffer[%d].\n",i);
			free(buffer_alice[i].data);
			buffer_alice[i].data = NULL;
			buffer_alice[i].datalen = 0;
		}
	}
	signal(SIGALRM, sigalrm_handler);
}

/*
 * Injects a single bit-error in sequence stored in the `buf' buffer.
 * buf - A pointer to the beginning of the buffer.
 * len - Lenght of the buffer.
 * Returns 0 if no error was injected or 1 if a single bit error was injected.
 */
int inject_biterror(void *buf, size_t len) {
	if ((random() % 100) < biterror_rate) {
		size_t index = (random() % len);
		int bit = (random() % 8);
		char biterrmask = 0x1 << bit;
		((char*)buf)[index] ^= biterrmask;
		return index * 8 + bit;
	}
	return 0;
}

int main(int argc, char **argv ) {
	char ch;
	while ((ch = getopt(argc,argv,"GgD:J:Q:R:a:A:b:B:l:o:h")) != -1) {
		switch(ch) {
		case 'G':
			debug_level = 2;
			break;
		case 'g':
			debug_level = 1;
			break;
		case 'a':
			remote_alice_port = atol(optarg);
			break;
		case 'A':
			local_alice_port = atol(optarg);
			break;
		case 'b':
			remote_bob_port = atol(optarg);
			break;
		case 'B':
			local_bob_port = atol(optarg);
			break;
		case 'D':
			delay = atol(optarg);
			break;
		case 'J':
			jitter = atol(optarg);
			break;
	  	case 'Q':
			queue_size = atol(optarg);
			break;
		case 'R':
			biterror_rate = atol(optarg);
			break;
		case 'l':
			addr_alice = ntohl(inet_addr(optarg)); //!!! needs nhotl as udt requires host order!
			break;
		case 'o':
			addr_bob = ntohl(inet_addr(optarg)); //!!! needs nhotl as udt requires host order!
			break;
		case 'h':
			// print help:
			fprintf(stdout, PROGRAM_INFO);
			fprintf(stdout, "usage: udtproxy [-Q length] [-D delay] [-J jitter] [-R ratio]\n");
			fprintf(stdout, "                [-l address] [-o address]\n");
			fprintf(stdout, "                -a port -A port -b port -B port\n\n");
			fprintf(stdout, "  Q length    : sets the size of both queues to `len'\n" );
			fprintf(stdout, "  D delay     : sets the mean delay of packet processing to `delay' ms\n" );
			fprintf(stdout, "  J jitter    : sets the jitter of delay to `jitter' ms\n" );
			fprintf(stdout, "  R integer   : sets the ratio of corrupted to correct packets to `ratio'/100.  \n\n" );
			fprintf(stdout, "  l address   : sets ip address of alice side to `address'\n" );
			fprintf(stdout, "  o address   : sets ip address of bob side to `address'\n\n" );
			fprintf(stdout, "  a port      : sets remote port of alice side to `port'\n" );
			fprintf(stdout, "  A port      : sets local port of alice side to `port'\n" );
			fprintf(stdout, "  b port      : sets remote port of bob side to `port'\n" );
			fprintf(stdout, "  B port      : sets local port of bob side to `port'\n" );
			exit(EXIT_SUCCESS);
			break;
		}
	}
	fprintf(stdout, PROGRAM_INFO);
	// Check if at least ports were specified:
	if (remote_alice_port==0 || local_alice_port==0 || remote_bob_port==0 || local_bob_port == 0) {
		fprintf(stderr,  "Missing arguments. All port numbers must be specified. Type '%s -h' for help.\n", PROGRAM);
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "Actual configuration:\n");
	fprintf(stdout, "Port map(bob->alice): %d -> %d => %d -> %d\n", remote_bob_port,
			local_bob_port, local_alice_port, remote_alice_port);
	fprintf(stdout, "Port map(alice->bob): %d -> %d => %d -> %d\n", remote_alice_port,local_alice_port, local_bob_port, remote_bob_port);
	fprintf(stdout,"Queue size: %d\n", queue_size);
	fprintf(stdout,"Extra delay: %dms, Jitter: %dms\n", delay, jitter);
	fprintf(stdout,"Bit-error rate: %d%% \n", biterror_rate);
	fprintf(stdout,"Debug level: %d \n", debug_level);

	void *aliceline[MAXLINE];
	void *bobline[MAXLINE];
	udt_alice = udt_init(local_alice_port);
	udt_bob = udt_init(local_bob_port);

	buffer_bob = (struct BufferPool*)malloc(sizeof(struct BufferPool)*queue_size);
	bzero(buffer_bob, sizeof(struct BufferPool)*queue_size);
	buffer_alice = (struct BufferPool*)malloc(sizeof(struct BufferPool)*queue_size);
	bzero(buffer_alice, sizeof(struct BufferPool)*queue_size);

	signal(SIGINT, sigint_handler);
	signal(SIGALRM, sigalrm_handler);
	struct itimerval itv;
	itv.it_interval.tv_sec = 0;
	itv.it_interval.tv_usec = 1000;
	itv.it_value.tv_sec = 0;
	itv.it_value.tv_usec = 1000;
	setitimer(ITIMER_REAL, &itv, NULL);

	sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGALRM);

	while (1) {
		int s;
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(udt_alice, &readfds);
		FD_SET(udt_bob, &readfds);
		if ( ( s = select(udt_bob+1, &readfds, NULL, NULL, NULL)) <= 0) continue;
		sigprocmask(SIG_BLOCK, &sigmask, NULL);
		if (FD_ISSET(udt_alice, &readfds)) {
			debug(1,  "Processing incoming packet from Alice:\n");
			packets_received++;
			int n = udt_recv(udt_alice, aliceline, MAXLINE, NULL, NULL);
			struct BufferPool *slot = find_empty_slot(buffer_alice, queue_size);
			if (slot != NULL) {
				slot->timeout = determine_delay(delay, jitter);
				int be_idx;
				if ((be_idx = inject_biterror(aliceline, n))) {
					packets_modified++;
					debug(1, "  Error injected at bit %d.\n", be_idx);
				}
				slot->data = memdup(aliceline, n);
				slot->datalen = n;
				debug(1,  "  Buffered in Alice's Buffer[%d] to be sent after %d ms.\n", (slot-buffer_alice), slot->timeout);
			} else {
				debug(1,  "  Drop packet because of full Alice's Buffer.\n");
				packets_dropped++;
			}
		}

		if (FD_ISSET(udt_bob, &readfds)) {
			debug(1, "Processing incoming packet from Bob:\n");
			packets_received++;
			int n = udt_recv(udt_bob, bobline, MAXLINE, NULL, NULL);
			struct BufferPool *slot = find_empty_slot(buffer_bob, queue_size);
			if (slot != NULL) {
				slot->timeout = determine_delay(delay, jitter);
				int be_idx;
				if ((be_idx = inject_biterror(bobline, n))) {
					packets_modified++;
					debug(1, "  Error injected at bit %d.\n", be_idx);
				}
				slot->data = memdup(bobline, n);
				slot->datalen = n;
				debug(1,  " Buffered in Bob's Buffer[%d] to be sent after %d ms.\n", (slot-buffer_bob), slot->timeout);
			} else {
				debug(1,  "  Drop packet because of full Bob's Buffer.\n");
				packets_dropped++;
			}
		}
		sigprocmask(SIG_UNBLOCK, &sigmask, NULL);
	}
}
