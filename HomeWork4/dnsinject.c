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
	unsigned short id; // identification number
	unsigned short flags; 
	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
}__attribute__((packed));

//Constant sized fields of query structure
struct QUESTION {
        unsigned short qtype;
        unsigned short qclass;
};
      
//Constant sized fields of the resource record structure
    struct R_DATA
    {
        unsigned short type;
        unsigned short _class;
        unsigned int ttl;
        unsigned short data_len;
    };
      
//Pointers to resource record contents
    struct RES_RECORD
    {
        unsigned char *name;
        struct R_DATA *resource;
        unsigned char *rdata;
    };
      
//Structure of a Query
    typedef struct
    {
        unsigned char *name;
        struct QUESTION *ques;
    } QUERY;

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

/*
 *  * dissect/print packet
 *   */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_udp *udp;		/* The UDP header*/
	int size_ip;
	bool frthr_analysis = false;
	unsigned offset = 0;
	struct DNS_HEADER *dns;
	struct QUESTION *question;

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
			printf("       From: %s\n", inet_ntoa(ip->ip_src));
			printf("         To: %s\n", inet_ntoa(ip->ip_dst));
			printf("   Src port: %d\n", ntohs(udp->uh_sport));
			printf("   Dst port: %d\n", ntohs(udp->uh_dport));
			offset = SIZE_ETHERNET + size_ip + SIZE_UDP;  
			dns = (struct DNS_HEADER *)(packet + offset);
 
     			printf("DNS ID : %d\n", ntohs(dns->id));
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

	printf("interface : %s\n", interface);
	printf("file : %s\n", file);
	printf("expr : %s\n", expr);

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
	index = search_hostname((unsigned char*)Map1, "www.fsl.com");
	if (index != -1) {
		printf("IP : %s\n", Map1->ip_addrs[index]);
	}

	if (!interface) {
		interface = pcap_lookupdev(errbuf);
		if (!interface) {
                	fprintf(stderr, "Couldn't find default device : %s\n", errbuf);
                        return (2);
                }
	}

	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
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
