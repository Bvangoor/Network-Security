#include <stdio.h>
#include <ctype.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

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
        for (j = 0; j < len; j++) {
                if (strcmp(Map1->hostnames[j], str) == 0) {
                        printf("Found IP : %s\n", Map1->ip_addrs[j]);
                        return j;
                }
        }
        printf("No IP Found\n");
	return -1;
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
	FILE * fp;
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
		fp = fopen(file, "r");
		if (fp == NULL) {
                	perror("open error");
                	return -1;
        	}
		while ((read = getline(&line, &len, fp)) != -1) {
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
	}

//	print_something();

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

		

	if (set)
		pcap_freecode(&fp);

	free(Map1);

	pcap_close(handle);
	
return 0;
}
