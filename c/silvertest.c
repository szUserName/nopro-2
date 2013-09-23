#include "stdio.h"
#include "stdlib.h"
#include "winsock2.h"   //need winsock for inet_ntoa and ntohs methods
#define HAVE_REMOTE
#include "pcap.h"   //Winpcap :)
#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib , "wpcap.lib") //For winpcap
// gcc -g silvertest.c -o silvertest.exe -lws2_32 -lwpcap

int main() {
	printf("PID: %d\n\n",getpid());
	unsigned char FinalPacket[5000];
	pcap_t *fp;
	u_int i, inum ;
	u_char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs, *d;
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}
	i = 0;
	for(d = alldevs; d; d = d->next) {
		printf("%d. %s\n    ", ++i, d->name);
		if (d->description) {
			printf(" (%s)\n", d->description);
		}
		else {
			printf(" (No description available)\n");
		}
	}
	if (i==0) {
		fprintf(stderr,"No interfaces found! Exiting.\n");
		return -1;
	}
	printf("Enter the interface number you would like to sniff : ");
	scanf("%d" , &inum);
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // Jump to the selected adapter
	if ((fp = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, errbuf)) == NULL) {
		fprintf(stderr,"\nError opening adapter\n");
		return -1;
	}
	memcpy((void*)FinalPacket,(void*)"\xFF\xFF\xFF\xFF\xFF\xFF\xCC\x0A\xF4\x6B\x70\xA8\x08\x06\x09\x4d\x2d\xa4\x0b\x68\xee\x88\xc9\x86\x0a\xab\xa4\x0b\x2d\x8d\x25\x6d\x66\x0c\x28\xac\xc6\xe6\x8a\xc8\xaa\xef\x26\x69\x29\x8c\xe8\xce\x2c\xfb",50);
	pcap_sendpacket(fp,FinalPacket,50);
	return 0;
}
