NAME    : Bharath Kumar Reddy Vangoor
SBU ID  : 110168461
Home Work 4 (3 extra days Used)

Submission contains following files :

1. Makefile	: File containing the rules to compile and generate the dnsinject and dnsdetect
2. dnsinject.c	: File containing the code for DNS Packet Injecting
3. dnsdetect.c	: File containing the code for DNS Packet Detecting
4. spoof.txt	: File containing list of IP address and hostname pairs to be hijacked
5. capture.pcap	: pcap file containing traffic taken containg some spoofed DNS packets, used for dnsdetect offline mode.

Instructions to run :

1. Compile :
	bharath@ubuntu:~/Network-Security/HomeWork4$ make
	gcc dnsinject.c -lpcap -o dnsinject
	gcc dnsdetect.c -lpcap -o dnsdetect

2. How to run :
	DNS Injection :
	bharath@ubuntu:~/Network-Security/HomeWork4$ ./dnsinject -h
	./dnsinject [-i interface] [-f file] expression
	-i  Listen on network device <interface> (e.g., eth0).
	-f  File with Ip addresses and Hostnames to be Hijacked
	<expression> is a BPF filter that specifies which packets will be monitored.
	
	DNS Detection :
	bharath@ubuntu:~/Network-Security/HomeWork4$ ./dnsdetect -h
	./dnsdetect [-i interface] [-r file] expression
	-i  Listen on network device <interface> (e.g., eth0).
	-r  Read packets from <file> (eg. ex.pcap) (tcpdump format).
	<expression> is a BPF filter that specifies which packets will be dumped.

3. Run (Examples) :
	 a) Hijacking "www.google.com" with IP address from "spoof.txt"
		Spoof file contents (Attacker Machine):
		root@ubuntu:/home/bharath/Network-Security/HomeWork4# cat spoof.txt 
		192.168.0.17	www.BOA.com
		192.168.186.12	www.google.com
		....

		DNS Inject Output (Attacker Machine) :
		root@ubuntu:/home/bharath/Network-Security/HomeWork4# ./dnsinject -i ens33 -f spoof.txt 
		Query Name : www.google.com
		SuccessFully sent Answer : 192.168.186.12 (76)

		NS Lookup Output (Victim Machine) :
		bharath@ubuntu:~$ nslookup www.google.com
		Server:		127.0.1.1
		Address:	127.0.1.1#53

		Non-authoritative answer:
		Name:	www.google.com
		Address: 192.168.186.12

		DNS Detection Output (Victim Machine) :
		root@ubuntu:/home/bharath/Network-Security/HomeWork4# ./dnsdetect -i ens33
		2016-05-09 13:28:18.423615 DNS poisoning attempt
		TXID 0x4873 Request www.google.com
		Answer1 [192.168.186.12, ]
		Answer2 [209.85.232.103, 209.85.232.99, 209.85.232.105, 209.85.232.106, 209.85.232.147, 209.85.232.104, ]

	b) Hijacking "www.google.com" with IP address of the Attacker Machine (No spoof.txt file)
		IP of Attacker Machine :
		bharath@ubuntu:~/Network-Security/HomeWork4$ ifconfig
		ens33     Link encap:Ethernet  HWaddr 00:0c:29:fa:f7:d5  
		inet addr:192.168.186.132  Bcast:192.168.186.255  Mask:255.255.255.0

		DNS Inject Output (Attacker Machine) :
		root@ubuntu:/home/bharath/Network-Security/HomeWork4# ./dnsinject -i ens33
		Query Name : www.google.com
		SuccessFully sent Answer : 192.168.186.132 (76)

		NS Lookup Output (Victim Machine) :
		bharath@ubuntu:~$ nslookup www.google.com
		Server:		127.0.1.1
		Address:	127.0.1.1#53

		Non-authoritative answer:
		Name:	www.google.com
		Address: 192.168.186.132

		DNS Detection Output (Victim Machine) :
		root@ubuntu:/home/bharath/Network-Security/HomeWork4# ./dnsdetect -i ens33
		2016-05-09 13:34:56.869630 DNS poisoning attempt
		TXID 0x9091 Request www.google.com
		Answer1 [192.168.186.132, ]
		Answer2 [209.85.232.147, 209.85.232.106, 209.85.232.104, 209.85.232.103, 209.85.232.99, 209.85.232.105, ]

	c) Dns Detection with pcap file containing spoofed responses
		root@ubuntu:/home/bharath/Network-Security/HomeWork4# ./dnsdetect -r capture.pcap 
		2016-05-08 13:23:25.177821 DNS poisoning attempt
		TXID 0xd5f8 Request www.google.com
		Answer1 [192.168.186.132, ]
		Answer2 [173.194.204.103, 173.194.204.106, 173.194.204.99, 173.194.204.105, 173.194.204.104, 173.194.204.147, ]

		2016-05-08 13:23:42.165380 DNS poisoning attempt
		TXID 0x126f Request www.BOA.com
		Answer1 [192.168.0.17, ]
		Answer2 [50.62.168.154, ]

		2016-05-08 13:24:15.228624 DNS poisoning attempt
		TXID 0x37ea Request www.fsl1.com
		Answer1 [127.0.0.2, ]
		Answer2 [173.201.93.128, ]

		2016-05-08 13:25:00.574641 DNS poisoning attempt
		TXID 0xb1ff Request www.cs.stonybrook.edu
		Answer1 [192.168.66.6, ]
		Answer2 [130.245.27.2, ]

Explaination :

1. Setup :
	a) Used VMware Fusion to create two VM's (Attacker and Victim), both have Ubuntu installed in it.
	
2. DnsInject :
	a) Parsing the command line arguments using "getopt" to take interface, filename, expression.

	b) Depending on the user arguments passed, we call "pcap_open_live", but even before that if no interface is passed we choose a default one using "pcap_lookupdev". I'm using promiscuous mode. If any spoof filename is passed then I parse those IP's and hostnames and store them in a Map.

	c) If user passes any BPF expression filter then we compile it using "pcap_compile" and set the filer to handle using "pcap_setfilter"

	d) Then we call "pcap_loop" which takes a call back function "got_packet" which is called whenever there is new packet that gets captured. I used maximum count of "1000" number of packets to be captured when this is reached "dnsinject" will exit, Also passing the Map that created in step b which is checked against the payload query hostname and corresponsing IP is sent back.

	e) Under "got_packet", I parse the IP header and check whether it is UDP or not, After that I parse UDP header and I only care about packets with destination port as 53.

	f) After that, I parse the DNS Header and then query from the QUESTION section. I check against my map if is ther any IP that I need to spoof. If I don't find anything I ignore the packet. If I find then I create a response packet.

	g) Constructing the Response, I copy the IP header from the incoming packet but swap the source and destination addresses. Then I copy the UDP header from incoing packet but swap the source and destination ports, also updating the checksum to 0. Then I copy the DNS Header and change the response flag and answer count to 1. Then I blindly copy the Query section without any changes. I add response structure with the IP I want to spoof and append to the response packet.

	h) Then I create the RAW socket and send the packet using "sendto()" function.

3. DnsDetect :
	a) Parsing the command line arguments using "getopt" to take interface, filename, expression

	b) Depending on the user arguments provided, if it is a filename then we call "pcap_open_offline" to create the pcap handle or if it is interface then we call "pcap_open_live", but even before that if no interface is passed we choose a default one using "pcap_lookupdev". I'm using promiscuous mode.

	c) If user passes any BPF expression filter then we compile it using "pcap_compile" and set the filer to handle using "pcap_setfilter"
	
	d) Then we call "pcap_loop" which takes a call back function "got_packet" which is called whenever there is new packet that gets captured. I used maximum count of "1000" number of packets to be captured when this is reached "dnsdetect" will exit

	e) Under "got_packet", I parse the IP header and check whether it is UDP or not, After that I parse UDP header and I only care about packets with source port as 53.

	f) After that, I parse DNS Header and then query string from the Question section. After I parse the response answers from the Response section. I will store transaction ID, query, time, udp checksum, answers inside my node structure and check against my previous parsed packets. And I insert every node into the list.

	g) These are the conditions I'm checking to raise DNS poisoning :
		i) Transaction ID is same
		ii) Query is same
		iii) Answers are different
		iv) one of the packets UDP checksum is 0.
		v) Finally, Check the packet timings are in the window of 1 sec (1000 msec)

References:
1. A simple implementation of DNS query : http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
