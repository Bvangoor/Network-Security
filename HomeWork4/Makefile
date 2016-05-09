all : dnsinject dnsdetect

dnsinject :
	gcc dnsinject.c -lpcap -o dnsinject

dnsdetect :
	gcc dnsdetect.c -lpcap -o dnsdetect

clean :
	rm -rf dnsinject
	rm -rf dnsdetect
