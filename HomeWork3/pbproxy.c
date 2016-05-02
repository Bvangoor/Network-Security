#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <openssl/aes.h>
#include <openssl/rand.h>


#define FILELEN 32
#define SLEEPTIME 20000

int ascii_to_hex(char c)
{
	int num = (int) c;
	if(num < 58 && num > 47)
		return num - 48;
        if(num < 103 && num > 96)
		return num - 87;
        return num;
}

struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
 *  *     * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);
    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}


void print_usage(void) {
	printf("./pbproxy [-l port] -k keyfile dest_IP dest_port\n");
	printf("-l  Listen on port (in case of server, eg : 22 etc)\n");
	printf("-k  Symmetric key contained in <keyfile> (as hexa decimal string)\n");
	printf("dest_IP  Destination IP address to connect\n");
	printf("dest_port  Destination Port to connect\n");
}

#define BUFSIZE 4096
#define MAX_CONNECTIONS 5

int maximum(int a, int b) {
	if (a > b)
		return a;
	return b;
}

int main(int argc, char** argv) {
	char *keyfile = NULL;
	char *destinationIP = NULL;
	char *resolved_keyfile = NULL;
	int listenPort = -1;
	int destinationPort = -1;
	int index;
	int c, i;
	int res = 0;
	int socketFd = -1;
	int socketsshfd = -1;
	int childFd;
	int flags;
	struct hostent *server;
	struct hostent *hostp; /*client host info*/
	char *hostaddrp;
	int optval; /* flag value for setsockopt */
	struct sockaddr_in serveraddr;
	struct sockaddr_in serversshaddr;
	struct sockaddr_in clientaddr;
	unsigned char indata[AES_BLOCK_SIZE];
        unsigned char outdata[AES_BLOCK_SIZE];
        unsigned char iv[AES_BLOCK_SIZE];
        struct ctr_state state;
        AES_KEY key;
        unsigned char enc_key[16], temp_key[16]; /*Key*/
	FILE *fp;
	unsigned char c1,c2;
	unsigned char sum;
	int clientlen;
	char buffer[BUFSIZE];
	char cipher[AES_BLOCK_SIZE + BUFSIZE];
	int read_bytes;
	int written_bytes;
	fd_set read_fds;

	if (argc < 2) {
		print_usage();
		return 1;
	}
	
	opterr = 0;
	while (c = getopt(argc, argv, "hl:k:")) {
		switch (c) {
			case 'h' :
				print_usage();
				return;
			case 'l' :
				listenPort = atoi(optarg);
				break;
			case 'k' :
				keyfile = optarg;
				break;
			case '?' :
				if (optopt == 'l' || optopt == 'k')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					fprintf(stderr, "Unknown option -%c.\n", optopt);
				else
					fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				print_usage();
				return 1;
			default :
				goto out;
		}
	}
out :
	index = optind;

	if (index < argc)
		destinationIP = argv[index];

	index++;

	if (index < argc)
		destinationPort = atoi(argv[index]);

	if (!keyfile) {
		printf("Provide keyfile argument\n");
		return 1;
	} else {
		resolved_keyfile = realpath(keyfile, NULL);
		/*File Exists*/
		if (!resolved_keyfile) {
			perror(keyfile);
			return 1;
		}
		/*Permissions*/
		if (access(resolved_keyfile, R_OK)) {
			perror(keyfile);
			return 1;
		}
	}

	/*Parsing the hexa decimal string to char*/
	fp = fopen(resolved_keyfile, "r");
	for( i = 0 ; i < FILELEN/2 ; i++)
	{
		c1 = ascii_to_hex(fgetc(fp));
		c2 = ascii_to_hex(fgetc(fp));
		sum = c1<<4 | c2;
		enc_key[i] = sum;
	}
	fclose(fp);
	
	if (!destinationIP) {
		printf("Provide Destination address to Connect\n");
		return 1;
	}

	if (destinationPort == -1) {
		printf("Provide Destination Port to Connect\n");
		return 1;
	}

	if (listenPort == -1) {
		/*client*/
		goto client;
	} else {
		/*server*/
		goto server;
	}

client :
	/*Initialise the encryption key*/
        if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
                fprintf(stderr, "Could not set encryption key.");
		res = -1;
                goto clientout;
        }
	
	/*Create the socket*/
	socketFd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketFd == -1) {
		perror("socket error");
		res = errno;
		goto clientout;
	}

	/*get host by name : get server's DNS entry*/
	server = gethostbyname(destinationIP);
	if (!server) {
		fprintf(stderr, "ERROR, No such host as %s\n", destinationIP);
		goto clientout;
	}

	/*build the server's Internet address*/
	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	bcopy((char *) server->h_addr, 
		(char *) &serveraddr.sin_addr.s_addr, server->h_length);
	serveraddr.sin_port = htons(destinationPort);

	/*Connect : Create a connection with server*/
	res = connect(socketFd, (struct sockaddr *) &serveraddr, sizeof(serveraddr));
	
	if (res == -1) {
		perror("Connection Error");
		res = errno;
		goto clientout;
	}
	bzero(buffer, BUFSIZE);
	memcpy(buffer, enc_key, 16);
	written_bytes = write(socketFd, buffer, 16);

	while (1) {
		/*Add stdin, socket to read file descriptors*/
		FD_ZERO(&read_fds);
		FD_SET(STDIN_FILENO, &read_fds);
		FD_SET(socketFd, &read_fds);

		/*Wait for any fds to be signalled for read*/
		res = select(socketFd+1, &read_fds, NULL, NULL, NULL);
		if (res < 0) {
			perror("Socket Error");
			res = errno;
			goto clientout;
		}

		/*Check if stdin is marked for read*/
		if (FD_ISSET(STDIN_FILENO, &read_fds)) {
			bzero(buffer, BUFSIZE);
			bzero(cipher, AES_BLOCK_SIZE + BUFSIZE);
			bzero(iv, AES_BLOCK_SIZE);
			read_bytes = read(STDIN_FILENO, buffer, BUFSIZE);
			/*encrypt*/
			/*Initialise the iv vector*/
                	if(!RAND_bytes(iv, AES_BLOCK_SIZE)) {
                        	fprintf(stderr, "Could not create random bytes.");
                        	res = -1;
				goto clientout;
                	}
			/*Initialise the state */
			init_ctr(&state, iv);
			memcpy(cipher, iv, AES_BLOCK_SIZE);
			AES_ctr128_encrypt(buffer, cipher + AES_BLOCK_SIZE, read_bytes, &key, state.ivec, state.ecount, &state.num);
			
			written_bytes = write(socketFd, cipher, AES_BLOCK_SIZE + read_bytes);
			usleep(SLEEPTIME);
			if (written_bytes < 0) {
				perror("Socket Write Error");
				res = errno;
				goto clientout;
			}
		} else if (FD_ISSET(socketFd, &read_fds)) { /*Check if socket is marked for read*/
			bzero(cipher, AES_BLOCK_SIZE + BUFSIZE);
			bzero(buffer, BUFSIZE);
			bzero(iv, AES_BLOCK_SIZE);
			read_bytes = read(socketFd, cipher, AES_BLOCK_SIZE + BUFSIZE);
			/*decrypt*/
			/*Get the IV*/
			memcpy(iv, cipher, AES_BLOCK_SIZE);
			/*Initialise the state*/
			init_ctr(&state, iv);
			AES_ctr128_encrypt(cipher + AES_BLOCK_SIZE, buffer, read_bytes - AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
			written_bytes = write(STDOUT_FILENO, buffer, read_bytes - AES_BLOCK_SIZE);
			usleep(SLEEPTIME);
                        if (written_bytes < 0) {
                                perror("Socket Write Error");
                                res = errno;
                                goto clientout;
                        }
		}
	}

clientout :
	if (socketFd != -1)
		close(socketFd);
	if (resolved_keyfile)		
		free(resolved_keyfile);
	return res;

server :
	/*Initialise the encryption key*/
        if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
                fprintf(stderr, "Could not set encryption key.");
                res = -1;
                goto serverout;
        }

	/*Create the socket*/
	socketFd = socket(AF_INET, SOCK_STREAM, 0);
        if (socketFd == -1) {
                perror("socket error");
                res = errno;
                goto clientout;
        }

	optval = 1;
	setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, 
	     (const void *)&optval , sizeof(int));

	/*Initialize socket structure*/
	bzero((char *)&serveraddr, sizeof(serveraddr));
	
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = INADDR_ANY; /**/
	serveraddr.sin_port = htons(listenPort); /*2222*/
	
	/*Now bind the host address using bind() call*/
	res = bind(socketFd, (struct sockaddr *) &serveraddr, sizeof(serveraddr));
	if (res == -1) {
		perror("Bind Error");
		res = errno;
		goto serverout;
	}
	/*Now Start listening for the clients*/
	res = listen(socketFd, MAX_CONNECTIONS);
	if (res == -1) {
		perror("Listen Error");
		res = errno;
		goto serverout;
	}

	clientlen = sizeof(clientaddr);

	while (1) {
waiting :
		/*Accept : Wait for a connection request*/
		childFd = accept(socketFd, (struct sockaddr *) &clientaddr, &clientlen);
		if (childFd < 0) {
			perror("Accept Error");
			res = errno;
			goto serverout;
		}
		
		/*Get the client details*/
		hostp = gethostbyaddr((const char *) &clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);

		if (!hostp) {
			perror("Host Addr Error");
			res = errno;
			goto serverout;
		}

		hostaddrp = inet_ntoa(clientaddr.sin_addr);
		if (!hostaddrp) {
			perror("Inet Ntoa Error");
			res = errno;
			goto serverout;
		}
		bzero(buffer, BUFSIZE);
		usleep(SLEEPTIME);
		read_bytes = read(childFd, temp_key, 16);
/*		for (i = 0; i < 16; i++)
			printf("%02x %02x\n", temp_key[i], enc_key[i]);*/
		if (read_bytes > 0) {
			for (i = 0; i < 16 ; i++) {
				if (temp_key[i] != enc_key[i]) {
					printf("Key MisMatch\n");
					close(childFd);
					printf("Server Closed connection with %s (%s)\n", hostp->h_name, hostaddrp);
					goto waiting;
				} //else {
//					printf("%02x %02x\n", temp_key[i], enc_key[i]);
//				}
			}
		} else {
//			printf("Time out for key\n");
			close(childFd);
			goto waiting;
		}
		printf("Server Established connection with %s (%s)\n", hostp->h_name, hostaddrp);
/*=======================================================================================================*/
		/*Establish a socket to sshd server*/
        	socketsshfd = socket(AF_INET, SOCK_STREAM, 0);
        	if (socketsshfd == -1) {
                	perror("socket error");
                	res = errno;
                	goto serverout;
        	}

        	/*get host by name : get server's DNS entry*/
        	server = gethostbyname(destinationIP); /*local host*/
        	if (!server) {
                	fprintf(stderr, "ERROR, No such host as %s\n", destinationIP);
                	goto serverout;
        	}

        	/*build the server's Internet address*/
        	bzero((char *) &serversshaddr, sizeof(serversshaddr));
        	serversshaddr.sin_family = AF_INET;
        	bcopy((char *) server->h_addr,
                	(char *) &serversshaddr.sin_addr.s_addr, server->h_length);
        	serversshaddr.sin_port = htons(destinationPort); /*22*/

        	/*Connect : Create a connection with server*/
        	res = connect(socketsshfd, (struct sockaddr *) &serversshaddr, sizeof(serversshaddr));

        	if (res == -1) {
                	perror("Connection Error");
                	res = errno;
                	goto serverout;
        	}
/*========================================================================================================*/	
		/*Do the main Stuff*/
		while (1) {
			 /*Add childfd, socketssh to read file descriptors*/
			FD_ZERO(&read_fds);
			FD_SET(childFd, &read_fds);
			FD_SET(socketsshfd, &read_fds);

			/*Wait for any fds to be signalled for read*/
			res = select(maximum(childFd, socketsshfd)+1, &read_fds, NULL, NULL, NULL);
			if (res < 0) {
				perror("Select Error");
				res = errno;
				goto serverout;
			}

			/*Check if stdin is marked for read*/
			if (FD_ISSET(childFd, &read_fds)) {
				bzero(cipher, AES_BLOCK_SIZE + BUFSIZE);
				bzero(buffer, BUFSIZE);
				bzero(iv, AES_BLOCK_SIZE);

				read_bytes = read(childFd, cipher, AES_BLOCK_SIZE + BUFSIZE);
				if (read_bytes == 0) {
					printf("Server Closed connection with %s (%s)\n", hostp->h_name, hostaddrp);
					break;
				}
				/*decrypt*/
				/*Initialise the IV*/
				memcpy(iv, cipher, AES_BLOCK_SIZE);
				
				/*Initialise the state*/
	                        init_ctr(&state, iv);
				AES_ctr128_encrypt(cipher + AES_BLOCK_SIZE, buffer, read_bytes - AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);	
				written_bytes = write(socketsshfd, buffer, read_bytes - AES_BLOCK_SIZE);
				usleep(SLEEPTIME);
				if (written_bytes < 0) {
					perror("Socket Write Error");
					res = errno;
					goto serverout;
				}
			} else if (FD_ISSET(socketsshfd, &read_fds)) { /*Check if socket is marked for read*/
				bzero(buffer, BUFSIZE);
				bzero(cipher, AES_BLOCK_SIZE + BUFSIZE);
				bzero(iv, AES_BLOCK_SIZE);

				read_bytes = read(socketsshfd, buffer, BUFSIZE);
				/*encrypt*/
				/*Initialise the iv vector*/
	                        if(!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        	                        fprintf(stderr, "Could not create random bytes.");
               		                res = -1;
                       	        	goto serverout;
                        	}
				/*Initialise the state */
	                        init_ctr(&state, iv);
                	        memcpy(cipher, iv, AES_BLOCK_SIZE);
				AES_ctr128_encrypt(buffer, cipher + AES_BLOCK_SIZE, read_bytes, &key, state.ivec, state.ecount, &state.num);
				written_bytes = write(childFd, cipher, AES_BLOCK_SIZE + read_bytes);
				usleep(SLEEPTIME);
				if (written_bytes < 0) {
					perror("Socket Write Error");
					res = errno;
					goto serverout;
				}
			}
		}
		close(socketsshfd);
		close(childFd);
	}

serverout :
	if (socketFd != -1)
                close(socketFd);
	if (resolved_keyfile)
		free(resolved_keyfile);
	return 0;
}
