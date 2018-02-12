/*
	Purpose:
		Demonstrate a PoC for dealing with raw sockets. The driver for this was to 
		provide an interface for spoofing a source IPv4 address.

		This is a proof of concept and is not intended to:
		- Be free of bugs
		- Be used maliciously
		- Target any asset without prior authorization
		- Be modified with any intent outside of personal research or learning
	Developer:
		darkestb4light (https://github.com/darkestb4light)
	Note:
		To get deeper than the typical app layer, we need to deal with raw sockets. 
		This requires elevated privileges since you could do evil things. 

		The source argument passed will be inputted into the source address field 
		of the IP header. 

		If you feel like modifying TCP flags, see the definition constants below 
		(prefixed with "TCP_FLAG_"). They can be enabled (1) or disabled (0). This 
		will require a recompile upon each change. IMPORTANT: It is recommended to 
		avoid modifying any values outside of TCP flags unless you know what you 
		are doing.

		On BSD systems (OSX and FREEBSD), spoofing 127.0.0.1 causes sendto(2) to 
		fail with: "Can't assign requested address". Use "localhost" or another 
		IPv4 address. The former will use the broadcast address as the source.

		Compile: 
		
		$ gcc -D <TARGET-OS> -o spoof spoof.c

		Where <TARGET-OS> is one of: LINUX, FREEBSD, or OSX

		Usage:

		spoof <src> <dst> <dport>

		<src>	# the source address to spoof
		<dst>	# the destination address of the victim to send the packet to
		<dport> # the TCP destination port to send the packet to
		
		Execute:
		
		$ sudo ./spoof 123.45.67.8 192.168.0.10 55555
		
		The above will spoof the source address "123.45.67.8" and send a packet 
		to the destination "192.168.0.10" over TCP port 55555.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#ifdef LINUX
	#include <linux/ip.h>
	#include <linux/tcp.h>
#elif FREEBSD | OSX
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netinet/ip.h>
	#include <netinet/tcp.h>
#else
	#error Target OS macro not specified or unsupported.
	#error Use supported macro: -D LINUX, -D FREEBSD, or -D OSX
	#error Aborting compilation.
#endif

#ifdef OSX
	#define AVOID_IPLEN_HTONS 1
#else
	#define AVOID_IPLEN_HTONS 0
#endif

#define NAME	"spoof"
#define MAX_ARG 4

/* Flags for IP header */
#define IP_HDRLEN 5			/* header length */
#define IP_VER 4			/* version */
#define IP_TYPEOFSERV 0		/* type of service */
#define IP_TOTLEN 0			/* total length (computed after building IP/TCP headers) */
#define IP_FRAGOFF 0		/* fragment offset */
#define IP_TIMETOLIVE 64	/* time to live */
#define IP_PROTO 6			/* protocol */
#define IP_CHKSUM 0			/* checksum */

/* Flags for TCP header */
#define TCP_DATAOFF 5		/* data offset */
#define TCP_CHECKSUM 0		/* checksum */
#define TCP_FLAG_FIN 0		/* finished; enable == 1, disable == 0 */
#define TCP_FLAG_SYN 1		/* sync; enable == 1, disable == 0 */
#define TCP_FLAG_RST 0		/* reset; enable == 1, disable == 0 */
#define TCP_FLAG_PSH 0		/* push; enable == 1, disable == 0 */
#define TCP_FLAG_ACK 0		/* acknowledgement; enable == 1, disable == 0 */
#define TCP_FLAG_URG 0		/* urgent; enable == 1, disable == 0 */
#define TCP_FLAG_ECE 0		/* explicit congestion (notification) echo */
#define TCP_FLAG_CWR 0		/* congestion window reduced */

int main(int argc, char **argv)
{
	int 				dport, sd, pktsz, optval = 1;
	const char 			*src, *dst;
	unsigned char 		data[0]; /* no data segment */
	struct sockaddr_in 	sin;
	struct tcphdr 		tcp_hdr;
	 
	if(argc != MAX_ARG){
		fprintf(stderr, "Usage:\n\n%s %s\n\n%s\n%s\n%s\n", 
			NAME, "<src> <dst> <dport>", 
			"<src>	# the source address to spoof", 
			"<dst>	# the destination address of the victim to send the packet to",
			"<dport> # the TCP destination port to send the packet to");              
		return 1;
	}
	
	src = argv[1];
	dst = argv[2];
	dport = atoi(argv[3]);
	
	if(dport < 0 || dport > 65535){
		fprintf(stderr, "%s: destination port outside of range: %d\n", NAME, dport);
		return 1;
	}

    /* socket address */
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dport);
	sin.sin_addr.s_addr = inet_addr(dst);

#ifdef LINUX
	struct iphdr ip_hdr;
	
	/* IP header */	
    ip_hdr.ihl = IP_HDRLEN;
    ip_hdr.version = IP_VER;
    ip_hdr.tos = IP_TYPEOFSERV;
    ip_hdr.tot_len = IP_TOTLEN;
    ip_hdr.frag_off = IP_FRAGOFF;
    ip_hdr.ttl = IP_TIMETOLIVE;
    ip_hdr.protocol = IP_PROTO;
    ip_hdr.check = IP_CHKSUM;
	ip_hdr.id = htons(rand() % 65535);
    ip_hdr.saddr = inet_addr(src);
    ip_hdr.daddr = inet_addr(dst);  
	
	/* TCP header */
	tcp_hdr.doff = TCP_DATAOFF;
	tcp_hdr.fin = TCP_FLAG_FIN;
	tcp_hdr.syn = TCP_FLAG_SYN;
	tcp_hdr.rst = TCP_FLAG_RST;
	tcp_hdr.psh = TCP_FLAG_PSH;
	tcp_hdr.ack = TCP_FLAG_ACK;
    tcp_hdr.urg = TCP_FLAG_URG;
	tcp_hdr.ece = TCP_FLAG_ECE;	
	tcp_hdr.cwr = TCP_FLAG_CWR;
	tcp_hdr.check = TCP_CHECKSUM;
	tcp_hdr.window = htons(0);
	tcp_hdr.urg_ptr = htons(0);
	tcp_hdr.source = htons(rand() % 65535);
	tcp_hdr.dest = htons(dport);
	tcp_hdr.seq = htonl(0);
	tcp_hdr.ack_seq = htonl(0);
	
	ip_hdr.tot_len = htons(sizeof(ip_hdr) + sizeof(tcp_hdr) + sizeof(data));
#elif FREEBSD | OSX
	struct ip ip_hdr;
	unsigned int tcp_flags = 0;
	
	/* IP header */	
    ip_hdr.ip_hl = IP_HDRLEN;
    ip_hdr.ip_v = IP_VER;
    ip_hdr.ip_tos = IP_TYPEOFSERV;
    ip_hdr.ip_len = IP_TOTLEN;
    ip_hdr.ip_off = IP_FRAGOFF;
    ip_hdr.ip_ttl = IP_TIMETOLIVE;
    ip_hdr.ip_p = IP_PROTO;
    ip_hdr.ip_sum = IP_CHKSUM;
	ip_hdr.ip_id = htons(rand() % 65535);
	ip_hdr.ip_src.s_addr = inet_addr(src);
    ip_hdr.ip_dst.s_addr = inet_addr(dst);
	
	/* TCP header */
	tcp_hdr.th_off = TCP_DATAOFF;
	if(TCP_FLAG_FIN) tcp_flags |= TH_FIN;
	if(TCP_FLAG_SYN) tcp_flags |= TH_SYN;
	if(TCP_FLAG_RST) tcp_flags |= TH_RST;
	if(TCP_FLAG_PSH) tcp_flags |= TH_PUSH;
	if(TCP_FLAG_ACK) tcp_flags |= TH_ACK;
	if(TCP_FLAG_URG) tcp_flags |= TH_URG;
	if(TCP_FLAG_ECE) tcp_flags |= TH_ECE;
	if(TCP_FLAG_CWR) tcp_flags |= TH_CWR;
	tcp_hdr.th_flags = tcp_flags;
	tcp_hdr.th_sum = TCP_CHECKSUM;
	tcp_hdr.th_win = htons(0);
	tcp_hdr.th_urp = htons(0);
	tcp_hdr.th_sport = htons(rand() % 65535);
	tcp_hdr.th_dport = htons(dport);
	tcp_hdr.th_seq = htonl(0);
	tcp_hdr.th_ack = htonl(0);
	
	if(AVOID_IPLEN_HTONS)
		ip_hdr.ip_len = sizeof(ip_hdr) + sizeof(tcp_hdr) + sizeof(data);
	else
		ip_hdr.ip_len = htons(sizeof(ip_hdr) + sizeof(tcp_hdr) + sizeof(data));
#else	/* should never fire if macro definitions are in sync */
	fprintf(stderr, "%s: Target OS macro integrity issue. Aborting.\n", NAME);
	return 1;
#endif
	
    pktsz = sizeof(ip_hdr) + sizeof(tcp_hdr) + sizeof(data);
    
	/* create socket */
	if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
		fprintf(stderr, "%s: socket: %s\n", NAME, strerror(errno));
		return 1;
	}
	
	printf("%s: socket descriptor created.\n", NAME);
	
	/* set socket options */
	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0){
		fprintf(stderr, "%s: setsockopt: %s\n", NAME, strerror(errno));
		return 1;
	}
	
	printf("%s: socket options set.\n", NAME);
	
	/* build packet */
	unsigned char pkt[pktsz];
	memcpy(pkt, &ip_hdr, sizeof(ip_hdr));
	memcpy(pkt + sizeof(ip_hdr), &tcp_hdr, sizeof(tcp_hdr));
	memcpy(pkt + sizeof(ip_hdr) + sizeof(tcp_hdr), data, sizeof(data));
	
	/* send packet */
	if(sendto(sd, pkt, sizeof(pkt), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
		fprintf(stderr, "%s: sendto: %s\n", NAME, strerror(errno));
		return 1;
	}

	printf("%s: packet sent from %s to %s:%d.\n", NAME, src, dst, dport);

	return 0;
}
