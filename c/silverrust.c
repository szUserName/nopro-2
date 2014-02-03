#include "string.h"
#include "stdio.h"
#include "stdlib.h"
#define HAVE_REMOTE
#include "pcap.h"
// gcc -g silvermac.c -o silvermac -lpcap

void ProcessPacket (const unsigned char*, int);
void PrintData (const unsigned char*, int);
void ParseInstruction (const unsigned char*, int);

typedef struct ethernet_header {
    unsigned char dest[6];
    unsigned char source[6];
    unsigned short type;
}   ETHER_HDR;
typedef struct ip_header {
    unsigned char ipvh;
    unsigned char iptos;
    unsigned short iplen;
    unsigned short ipid;
    unsigned short ipfrag;
    unsigned char ipttl;
    unsigned char ipproto;
    unsigned short ipcheck;
    unsigned char ipsourceaddr[4];
    unsigned char ipdestaddr[4];
}   IP_HDR;
typedef struct udp_header {
	unsigned short udpsourceport;
	unsigned short udpdestport;
	unsigned short udplen;
	unsigned short udpcheck;
} UDP_HDR;

ETHER_HDR *ethhdr;
IP_HDR *iphdr;
UDP_HDR *udphdr;
unsigned char *data;

int main() {
	pcap_t *fp;
	int packet;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	unsigned int i, inum ;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs, *d;
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
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
	if ((fp = pcap_open_live(d->name, 4096, 1, 1000, errbuf)) == NULL) {
	//if ((fp = pcap_create(d->name, errbuf)) == NULL) {
		fprintf(stderr,"\nError opening adapter\n");
		return -1;
	}
	while ((packet = pcap_next_ex(fp, &header, &pkt_data) >= 0)) {
		if (packet == 0) {
			continue;
		}
		ProcessPacket(pkt_data , header->caplen);
	}
    if(packet == -1) {
        fprintf(stderr, "Error reading the packets: %s\n" , pcap_geterr(fp));
        return -1;
    }
	pcap_close(fp);
	return 0;
}

void ProcessPacket(const unsigned char* Buffer, int Size) {
    ethhdr = (ETHER_HDR *)Buffer;
    if (ntohs(ethhdr->type) == 0x0800) {
	    Buffer = (Buffer + 14); // skip 12 for mac addresses and 2 for ethertype
	    Size = (Size - 14);
	    PrintData(Buffer , Size);
    }
}
void PrintData (const unsigned char* data , int Size) {
	iphdr = (IP_HDR *)data;
	data = (data + ((iphdr->ipvh & 0x0f) * 4)); // skip ahead header length bytes
	Size -= ((iphdr->ipvh & 0x0f) * 4);
	if (iphdr->ipproto == 17) {
		udphdr = (UDP_HDR *)data;
		data = (data + 8);
		Size -= 8;
	}
	int i;
	i = 0;
	int InstructionLen;
	for (;i < Size;i++) {
		if (data[i] == 0x89) { // found new instruction byte
			InstructionLen = data[i+3]; // data length for this instruction
		    i += 4 + InstructionLen;
		    ParseInstruction(data, InstructionLen);
		}
	}
}

void ParseInstruction (const unsigned char* data , int Size) { // Instruction Parser
	unsigned char clientID[5];
	unsigned char clientName[65];
	int i;
	i = 0;
	int Instruction;
	Instruction = data[i++]; // instruction type
	switch (Instruction) {
		case 0x74: // new client found
			i += 64;
			int j;
			j = 0;
			for (;j < 4;j++) {
				clientID[j] = data[i + j];
			}
			i += 8;
			int k = data[i++];
			for (j = 0;j < k;j++) {
				clientName[j] = data[i + j];
			}
			printf("Name %s is ID %s\n", clientName, clientID);
		break;
		case 0x2e: // read client move
		break;
		case 0x7c: // get network update - we don't care about these probably
		break;
		default:
		break;
	}
}
