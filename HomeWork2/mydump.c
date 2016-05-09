#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */

struct sniff_icmp {
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct
    {
      u_int16_t	__unused;
      u_int16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};

#define ICMP_ECHOREPLY	0	/* Echo Reply	*/
#define ICMP_ECHO	8	/* Echo Request */

#define ARP_REQUEST	1	/* ARP Request*/ 
#define ARP_REPLY	2	/* ARP Reply*/ 
#define RARP_REQ_REV 	3
#define RARP_REPLY_REV	4

struct sniff_arp { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}; 

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;
	/* offset */
//printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 *  * print packet payload data (avoid printing binary data)
 *   */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;


	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}


/*
 *  * dissect/print packet
 *   */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;
	const struct sniff_icmp *icmp;
	const struct sniff_arp *arp, *rarp;
	const char *payload;                    /* Packet payload */
	int i;
	int size_ip;
	int size_tcp;
	int size_payload;
	struct timeval tv;
	time_t nowtime;
        struct tm *nowtm;
        char tmbuf[64], buf[64];
	bool tcp_packet = false, udp_packet = false, icmp_packet = false;
	
	printf("\nPacket length : %d\n", header->len);
	count++;
	
	tv = header->ts;
	nowtime = tv.tv_sec;
        nowtm = localtime(&nowtime);
        strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
        snprintf(buf, sizeof buf, "%s.%06d", tmbuf, tv.tv_usec);
	printf("Time Stamp : %s\n", buf);

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	printf("Source MAC Address : ");
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		printf("%02x", ethernet->ether_shost[i]);
		if (i != (ETHER_ADDR_LEN-1))
			printf(":");
	}
	printf("\n");
	printf("Destination MAC Address : ");
	for (i = 0; i<ETHER_ADDR_LEN; i++) {
                printf("%02x", ethernet->ether_dhost[i]);
                if (i != (ETHER_ADDR_LEN-1))
                        printf(":");
        }
        printf("\n");
	if (ntohs(ethernet->ether_type) == ETHERTYPE_IP)	
		printf("Ethernet Type : IP\n");
	else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
		printf("Ethernet Type : ARP\n");
		arp = (struct sniff_arp *)(packet + SIZE_ETHERNET);
		printf("Hardware type: %s\n", (ntohs(arp->htype) == 1) ? "Ethernet" : "Unknown"); 
  		printf("Protocol type: %s\n", (ntohs(arp->ptype) == 0x0800) ? "IPv4" : "Unknown"); 
		printf("Operation: %s\n", (ntohs(arp->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 
 
		 /* If is Ethernet and IPv4, print packet contents */ 
		if (ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800){ 
			printf("Sender MAC: "); 

			for(i=0; i<6;i++)
        			printf("%02X:", arp->sha[i]); 

    			printf("\nSender IP: "); 

    			for(i=0; i<4;i++)
        			printf("%d.", arp->spa[i]); 

    			printf("\nTarget MAC: "); 

    			for(i=0; i<6;i++)
        			printf("%02X:", arp->tha[i]); 

    			printf("\nTarget IP: "); 

    			for(i=0; i<4; i++)
        			printf("%d.", arp->tpa[i]); 
    
    			printf("\n"); 
  		}
		return ;
	}
	else if (ntohs(ethernet->ether_type) == ETHERTYPE_REVARP) {
		printf("Ethernet Type : REVARP\n");
		arp = (struct sniff_arp *)(packet + SIZE_ETHERNET);
                printf("Hardware type: %s\n", (ntohs(arp->htype) == 1) ? "Ethernet" : "Unknown");
                printf("Protocol type: %s\n", (ntohs(arp->ptype) == 0x0800) ? "IPv4" : "Unknown");
		
                printf("Operation : ");
		if ((ntohs(arp->oper) == RARP_REQ_REV))
			printf("RARP Request Reverse\n");
		else if ((ntohs(arp->oper) == RARP_REPLY_REV))
			printf("RARP Reply Reverse\n");

                 /* If is Ethernet and IPv4, print packet contents */
                if (ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800){
                        printf("Sender MAC: ");

                        for(i=0; i<6;i++)
                                printf("%02X:", arp->sha[i]);

                        printf("\nSender IP: ");

                        for(i=0; i<4;i++)
                                printf("%d.", arp->spa[i]);

                        printf("\nTarget MAC: ");

                        for(i=0; i<6;i++)
                                printf("%02X:", arp->tha[i]);

                        printf("\nTarget IP: ");

                        for(i=0; i<4; i++)
                                printf("%d.", arp->tpa[i]);

                        printf("\n");
                }
		return ;
	}
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			tcp_packet = true;
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			udp_packet = true;
			printf("   Protocol: UDP\n");
			break;
		case IPPROTO_ICMP:
			icmp_packet = true;
			printf("   Protocol: ICMP\n");
			break;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
//	printf("tcp_packet : %d, udp_packet : %d, icmp_packet : %d\n", tcp_packet, udp_packet, icmp_packet);	
	/* define/compute tcp header offset */
	if (tcp_packet) {
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
	
		printf("   Src port: %d\n", ntohs(tcp->th_sport));
		printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
		/* define/compute tcp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		/* compute tcp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	} else if (udp_packet) {
		/* define/compute udp header offset */
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	
		printf("   Src port: %d\n", ntohs(udp->uh_sport));
		printf("   Dst port: %d\n", ntohs(udp->uh_dport));
	
		/* define/compute udp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
	
		/* compute udp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
         	if (size_payload > ntohs(udp->uh_ulen))
                	 size_payload = ntohs(udp->uh_ulen);
	} else if (icmp_packet) {
		icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
		printf("Type : %d", (unsigned int)(icmp->type));
		if ((unsigned int)(icmp->type) == 11)
			printf("   (TTL Expired)\n");
		else if ((unsigned int)(icmp->type) == ICMP_ECHO)
			printf("   (ICMP Echo Request)\n");
		else if ((unsigned int)(icmp->type) == ICMP_ECHOREPLY)
			printf("   (ICMP Echo Reply)\n");
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(icmp));
		size_payload = ntohs(ip->ip_len) - (size_ip + sizeof(icmp));
	}

printpayload:	
	/*
 * 	 * Print payload data; it might be binary, so don't just
 * 	 	 * treat it as a string.
 * 	 	 	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		if (args) {
			const u_char *ch, *found = NULL;
			char tempbuf[size_payload];
			ch = payload;
        		for(i = 0; i < size_payload; i++) {
                		if (isprint(*ch))
                        		tempbuf[i] = *ch;
                		else
                        		tempbuf[i] = '.';
                		ch++;
        		}
			found = strstr(tempbuf, (char *)args);
			if (found) {
				printf("FOUND\n");	
				print_payload(payload, size_payload);
				return ;
			} else {
				printf("Not Found\n");
				return ;
			}
		}	
		print_payload(payload, size_payload);
	}

return;
}

void print_usage(void) {
	printf("./mydump [-i interface] [-r file] [-s string] expression\n");
	printf("-i  Listen on network device <interface> (e.g., eth0).\n");
	printf("-r  Read packets from <file> (tcpdump format).\n");
	printf("-s  Keep only packets that contain <string> in their payload.\n");
	printf("<expression> is a BPF filter that specifies which packets will be dumped.\n");
}

int main(int argc, char** argv) {
	int c, index;
	char *interface = NULL;
	char *file = NULL;
	char *strng = NULL;
	char *expr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = NULL;
	struct bpf_program fp;		/* The compiled filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	bool set = false;

	opterr = 0;
	while (c = getopt(argc, argv, "hi:r:s:")) {
		switch (c) {
			case 'h' :
				print_usage();
				return;
			case 'i' :
				interface = optarg;
				break;
			case 'r' :
				file = optarg;
				break;
			case 's' :
				strng = optarg;
				break;
			case '?' :
				if (optopt == 'i' || optopt == 'r' || optopt == 's')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					fprintf(stderr, "Unknown option -%c.\n", optopt);
				else
					fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				return 1;
			default :
				goto out;
		}
	}
out :
	for (index = optind; index < argc; index++)
		expr = argv[index];

	if (file) {
//		printf("Offline Case\n");
		interface = NULL;
		handle = pcap_open_offline(file, errbuf);
                if (!handle) {
                        fprintf(stderr, "Couldn't open device : %s\n", errbuf);
                        return (2);
                }
	} else {
		if (interface) {
//			printf("User Passed Interface : %s\n", interface);
		} else {
//			printf("Default interface needs to be used\n");
			interface = pcap_lookupdev(errbuf);
			if (!interface) {
				fprintf(stderr, "Couldn't find default device : %s\n", errbuf);
				return (2);
			}
//			printf("default interface : %s\n", interface);
		}
	}

	if (interface) {
		handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
		if (!handle) {
			fprintf(stderr, "Couldn't open device : %s\n", errbuf);
			return (2);
		}
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
		return (2);
	}
	
	if (expr) {
		if (interface && (pcap_lookupnet(interface, &net, &mask, errbuf) == -1)) {
			fprintf(stderr, "Can't get netmask for device %s\n", interface);
			net = 0;
			mask = 0;
		} else {
			net = 0;
			mask = 0;
		}
		if (pcap_compile(handle, &fp, expr, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", expr, pcap_geterr(handle));
			return(2);
		}
		set = true;
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", expr, pcap_geterr(handle));
			return(2);
		}
	}
	if (strng)
		pcap_loop(handle, 1000, got_packet, (u_char*)strng);
	else
		pcap_loop(handle, 1000, got_packet, NULL);

	if (set)
		pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}
