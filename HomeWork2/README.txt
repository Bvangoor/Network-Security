NAME 	: Bharath Kumar Reddy Vangoor
SBU ID 	: 110168461

Submission contains following files :

1. hw1.pcap	: pcap file took it from HomeWork1 to demonstarte the offline usecase for mydump
2. Makefile  	: File containing the rules to compile and generate the mydump
3. mydump.c	: File containg the Actual code.

Instructions to run :

1. Compile :
	[bvangoor@dhcp232 HomeWork2]$ make
	gcc mydump.c -lpcap -o mydump
2. How to run :
	[root@dhcp232 HomeWork2]# ./mydump -h
	./mydump [-i interface] [-r file] [-s string] expression
	-i  Listen on network device <interface> (e.g., eth0).
	-r  Read packets from <file> (tcpdump format).
	-s  Keep only packets that contain <string> in their payload.
	<expression> is a BPF filter that specifies which packets will be dumped.

3. Run (Examples) :
	a) A simple ping to www.google.com :
		[root@dhcp232 HomeWork2]# ./mydump -i ens32 icmp
		Packet length : 98
		Time Stamp : 2016-03-11 12:00:02.935868
		Source MAC Address : 00:50:56:8f:d5:f0
		Destination MAC Address : 00:1b:21:0c:f4:c6
		Ethernet Type : IP
       		From: 130.245.126.232
         	To: 172.217.1.68
   		Protocol: ICMP
		Type : 8   (ICMP Echo Request)
   		Payload (56 bytes):
		92 f9 e2 56 00 00 00 00  9f 47 0e 00 00 00 00 00    ...V.....G......
		10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f    ................
		20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f     !"#$%&'()*+,-./
		30 31 32 33 34 35 36 37                             01234567
	b) Offline using pcap file :
		[root@dhcp232 HomeWork2]# ./mydump -r hw1.pcap arp
		Packet length : 60
		Time Stamp : 2013-01-12 11:37:42.871346
		Source MAC Address : c4:3d:c7:17:6f:9b
		Destination MAC Address : ff:ff:ff:ff:ff:ff
		Ethernet Type : ARP
		Hardware type: Ethernet
		Protocol type: IPv4
		Operation: ARP Request
		Sender MAC: C4:3D:C7:17:6F:9B:
		Sender IP: 192.168.0.1.
		Target MAC: 00:00:00:00:00:00:
		Target IP: 192.168.0.12.

Explaination :

1. Parsing the command line arguments using "getopt" to take interface, filename, any string or expression

2. Depending on the user arguments provided, if it is a filename then we call "pcap_open_offline" to create the pcap handle or if it is interface then we call "pcap_open_live", but even before that if no interface is passed we choose a default one using "pcap_lookupdev". I'm using promiscuous mode.

3. If user passes any BPF expression filter then we compile it using "pcap_compile" and set the filer to handle using "pcap_setfilter"

4. Then we call "pcap_loop" which takes a call back function "got_packet" which is called whenever there is new packet that gets captured. I used maximum count of "1000" number of packets to be captured when this is reached "mydump" will exit, Also passing a string that user passes which is checked against the payload content and deciode whether to print or not.

5. Under "got_packet", First I parse the Ethernet Header (size of 14 bytes, header is in code) and print Src/Dest Mac Address and type of Ethernet (IP, ARP or RARP).

6. If it is ARP or RARP, I parse them using "sniff_arp" structure and print hardware type, protocol type, operation type, Sender/Target MAC address, Sender/Target IP.

7. If it is IP Packet, I print Src/Dest IP adrdess, print Protocol type (TCP, UDP or ICMP).

8. Depending on the protocol type I parse wither TCP, UDP or ICMP header (using sniff_tcp, sniff_udp, sniff_icmp structures defined in code) to print src/dest port and in case of icmp the paket type (echgo request or reply or TTL timeout)

9. At the end we prinmt the Payload, but before printing I'm checking if the payload contains the user passed string, otherwise I don't print it.
