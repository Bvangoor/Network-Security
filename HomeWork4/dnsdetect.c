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

#define TIME_THRESHOLD 1000 /*In msecs*/

long timevaldiff(struct timeval *starttime, struct timeval *finishtime)
{
  long msec;
  msec=(finishtime->tv_sec-starttime->tv_sec)*1000;
  msec+=(finishtime->tv_usec-starttime->tv_usec)/1000;
  return msec;
}


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

/* Length of DNS header. */
#define DNS_HDRLEN  12

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

/*My own Linked List to track Responses*/
struct node {
	unsigned txid:16;
	struct timeval tv;
	unsigned short uh_sum;
	char question[100];
	int anscount;
	char answers[20][16];
	struct node *next;
} *head;

void insert_to_list(struct node *temp) {
	if (head == NULL) {
		head = temp;
		return ;
	} else {
		temp->next = head;
		head = temp;
		return ;
	}
}

bool compare_queries(char *first, char *second) {

	if (strcmp(first, second) == 0)
		return true;
	return false;
}

bool compare_checksum(unsigned short csum1, unsigned short csum2) {

	if (ntohs(csum1)==0 || ntohs(csum2)==0)
		return true;
	return false;
}

bool compare_times(struct timeval *first, struct timeval *second) {
	long msec;

	msec = timevaldiff(first, second);
	if (msec <= TIME_THRESHOLD)
		return true;
	return false;
}

bool compare_answers(char **first, int count1, char **second, int count2) {
	int i, j, matches = 0;

	if (count1 != count2)
		return true;
	for (i = 0 ; i < count1; i++) {
		for (j = 0; j < count2; j++) {
			if (strcmp(first[i], second[j])==0)
				matches++;
		}
	}
	if (matches == count1)
		return false;
	return true;
}

struct node* lookup(struct node *temp) {
	struct node *temp1;

        temp1 = head;
	while (temp1) {
		if (temp1->txid == temp->txid) {
			bool query_same = false; /*Query Should be Same*/
			bool checksum_zero = false;  /*One of the packets checksum shoul be 0 (then it is spoofed)*/
			bool ans_different = false; /*Answers should be completely different*/
			bool time_diff = false;   /*Time diff should be inside the threshold value*/
			bool complex_stuff = false;
	
			query_same = compare_queries(temp1->question, temp->question);
	
			checksum_zero = compare_checksum(temp1->uh_sum, temp->uh_sum);

//			ans_different = compare_answers(temp1->answers, temp1->ans_count, 
//							temp->answers, temp->ans_count);
	
			time_diff = compare_times(&(temp->tv), &(temp1->tv));	/*First arg is later time*/
		
			if (ans_different) {
				if (checksum_zero)
					complex_stuff = true;
			} else {		/*I'm really crazy here*/
				if (checksum_zero)
                                        complex_stuff = true;
			}
			
			if (query_same && complex_stuff && time_diff)
				break;
		}
		temp1 = temp1->next;
	}

	return temp1;
}

struct node *Allocate_node() {
        struct node *temp;

        temp = (struct node*)malloc(sizeof(struct node));
        temp->next = NULL;
        return temp;
}

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


void print_usage(void) {
        printf("./dnsdetect [-i interface] [-r file] expression\n");
        printf("-i  Listen on network device <interface> (e.g., eth0).\n");
        printf("-r  Read packets from <file> (eg. ex.pcap) (tcpdump format).\n");
        printf("<expression> is a BPF filter that specifies which packets will be dumped.\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_udp *udp;            /* The UDP header*/
	int size_ip, count = 0;
	bool frthr_analysis = false;
	unsigned offset = 0;
	struct DNS_HEADER *dns;
	struct QUESTION *question;
	char *qname;
	const u_char *temp;
	unsigned int p = 0;
	int i, j, index;
        struct RES_RECORD *response;
	struct node *resp_node, *resp_node1;
	struct timeval packet_tv;

	packet_tv = header->ts;
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;

	if (size_ip < 20) {
//		printf("   * Invalid IP header length: %u bytes\n", size_ip); (don't print)
		return;
	}

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
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	
		if (ntohs(udp->uh_sport) == 53) {
			offset = SIZE_ETHERNET + size_ip + SIZE_UDP;

			dns = (struct DNS_HEADER *)(packet + offset);
			offset += DNS_HDRLEN;
			
			/* Parse the QNAMe until \0 */
                        temp = packet + offset;
                        int qname_len = 0, stop = 0;

                        qname = ReadName(temp, &qname_len);
			offset = qname_len; 
			question = (struct QUESTION *)(temp + offset);
			offset = offset + sizeof(struct QUESTION);
			
//			printf("Response Ans Count %d\n", ntohs(dns->ancount));
			count = ntohs(dns->ancount);

			resp_node = Allocate_node();
			resp_node->txid = dns->id;
			resp_node->tv = packet_tv;
			resp_node->uh_sum = udp->uh_sum;
			strncpy(resp_node->question, qname, strlen(qname));
			resp_node->anscount = 0;

			while (count > 0) {
				response = (struct RES_RECORD*)(temp + offset);
				if ((ntohs(response->type) == 1) && (ntohs(response->data_len) == 4)) {
					struct in_addr source;
					memset(&source, 0, sizeof(source));
					source.s_addr = response->rdata;
//					printf("Ans : %s\n", inet_ntoa(source));
					strcpy(resp_node->answers[resp_node->anscount], inet_ntoa(source));
					resp_node->anscount = (resp_node->anscount) + 1;
//					printf("Ans count in the node : %d\n", resp_node->anscount);
					offset = offset + sizeof(struct RES_RECORD);
				} else {
					offset = offset + 12 + ntohs(response->data_len);
				}
				count = count-1;
			}
			resp_node1 = lookup(resp_node);
			if (resp_node1) {
				int count1 = 0, ind = 0;
				printf("TXID 0x%x Request %s\n", dns->id, qname);
				printf("Answer1 [");
				count1 = resp_node->anscount;
				while (ind < count1) {
					printf("%s, ", resp_node->answers[ind]);
					ind++;
				}
				printf("]\n");
				printf("Answer2 [");
				count1 = resp_node1->anscount;
				ind = 0;
				while (ind < count1) {
					printf("%s, ", resp_node1->answers[ind]);
					ind++;
				}
				printf("]\n");	
			}
			insert_to_list(resp_node);
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

        opterr = 0;
	while (c = getopt(argc, argv, "hi:r:")) {
		switch (c) {
			case 'h' :
				print_usage();
				return 0;
			case 'i' :
				interface = optarg;
				break;
			case 'r' :
				file = optarg;
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
out:
	for (index = optind; index < argc; index++)
		expr = argv[index];

	if (file) {
		interface = NULL;
		handle = pcap_open_offline(file, errbuf);
		if (!handle) {
			fprintf(stderr, "Couldn't open device : %s\n", errbuf);
			return (2);
		}
	} else {
		if (interface) {
//                      printf("User Passed Interface : %s\n", interface);
		} else {
			interface = pcap_lookupdev(errbuf);
			if (!interface) {
				fprintf(stderr, "Couldn't find default device : %s\n", errbuf);
				return (2);
			}
		}
	}
	
	if (interface) {
		handle = pcap_open_live(interface, BUFSIZ, 1, -1, errbuf);
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

	pcap_loop(handle, 1000, got_packet, NULL);
		
	if (set)
		pcap_freecode(&fp);

	pcap_close(handle);

return 0;
}
