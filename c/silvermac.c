#include "string.h"
#include "stdio.h"
#include "stdlib.h"
#define HAVE_REMOTE
#include "pcap.h"
// gcc -g silvermac.c -o silvermac -lpcap

void ProcessPacket (const unsigned char* , int);
//void print_ethernet_header (u_char*);
void PrintData (const unsigned char* , int);

// I guess uchar is 1 byte, ushort is 2, uint is a full word, and doing "uchar something:n" is grab n bytes?
typedef struct nopro_header {
    unsigned char nopro_command;
}   NOPRO_HDR;
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
typedef struct tcp_header {
	unsigned short tcpsourceport;
	unsigned short tcpdestport;
	unsigned int tcpseq;
	unsigned int tcpack;
	unsigned char tcplen;
	unsigned char tcpflags;
	unsigned short tcpwindow;
	unsigned short tcpcheck;
	unsigned short tcpurg;
} TCP_HDR;
typedef struct udp_header {
	unsigned short udpsourceport;
	unsigned short udpdestport;
	unsigned short udplen;
	unsigned short udpcheck;
} UDP_HDR;

NOPRO_HDR *noprohdr;
ETHER_HDR *ethhdr;
IP_HDR *iphdr;
TCP_HDR *tcphdr;
UDP_HDR *udphdr;
u_char *data;

int main() {
//	printf("PID: %d\n\n",getpid());
	//unsigned char FinalPacket[5000];
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
//	memcpy((void*)FinalPacket,(void*)"\xFF\xFF\xFF\xFF\xFF\xFF\xCC\x0A\xF4\x6B\x70\xA8\x08\x06\x09\x4d\x2d\xa4\x0b\x68\xee\x88\xc9\x86\x0a\xab\xa4\x0b\x2d\x8d\x25\x6d\x66\x0c\x28\xac\xc6\xe6\x8a\xc8\xaa\xef\x26\x69\x29\x8c\xe8\xce\x2c\xfb",50);
//	pcap_sendpacket(fp,FinalPacket,50);
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
    //Ethernet header
    ethhdr = (ETHER_HDR *)Buffer;
    printf("-----------------------\nEthertype: %04x", ntohs(ethhdr->type));
    if (ntohs(ethhdr->type) == 0x0800) {
	    printf(" IP\n");
	    Buffer = (Buffer + 14); // skip 12 for mac addresses and 2 for ethertype
	    Size = (Size - 14);
	    PrintData(Buffer , Size);
    }
    else if (ntohs(ethhdr->type) == 0x0806) {
    	printf(" ARP\n");
    
    }
    else {
    	printf("\n");
    }
}
void PrintData (const unsigned char* data , int Size) { //    Print the hex values of the data
	iphdr = (IP_HDR *)data;
	printf("Ver %d Hlen %d TOS %02x Len %d ID %04x Frag %04x TTL %d Proto %d ",
			iphdr->ipvh >> 4,
			(iphdr->ipvh & 0x0f) * 4,
			iphdr->iptos,
			ntohs(iphdr->iplen),
			ntohs(iphdr->ipid),
			ntohs(iphdr->ipfrag),
			iphdr->ipttl,
			iphdr->ipproto);
	switch (iphdr->ipproto) {
            case 1:
		    printf("ICMP\n");
            break;
            case 2:
		    printf("IGMP\n");
            break;
            case 6:
		    printf("TCP\n");
            break;
            case 9:
		    printf("IGRP\n");
            break;
            case 17:
		    printf("UDP\n");
            break;
            case 47:
		    printf("GRE\n");
            break;
            case 50:
            printf("ESP\n");
            break;
            case 51:
            printf("AH\n");
            break;
            case 57:
            printf("SKIP\n");
            break;
            case 88:
            printf("EIGRP\n");
            break;
            case 89:
            printf("OSPF\n");
            break;
            case 115:
            printf("L2TP\n");
            break;
 
            default:
		    printf("Other\n");
            break;
        }
	printf("SrcIP %d.%d.%d.%d DstIP %d.%d.%d.%d\n",
			iphdr->ipsourceaddr[0],iphdr->ipsourceaddr[1],iphdr->ipsourceaddr[2],iphdr->ipsourceaddr[3],
			iphdr->ipdestaddr[0],iphdr->ipdestaddr[1],iphdr->ipdestaddr[2],iphdr->ipdestaddr[3]);
	data = (data + ((iphdr->ipvh & 0x0f) * 4)); // skip ahead header length bytes
	Size -= ((iphdr->ipvh & 0x0f) * 4);
	if (iphdr->ipproto == 6) {
		tcphdr = (TCP_HDR *)data;
		printf("SrcPort %d DstPort %d\nSeq %08x Ack %08x Len %d Flags %d\nWindow %04x Urg %04x\n",
				ntohs(tcphdr->tcpsourceport),
				ntohs(tcphdr->tcpdestport),
				ntohl(tcphdr->tcpseq),
				ntohl(tcphdr->tcpack),
				(tcphdr->tcplen >> 4) * 4,
				(tcphdr->tcpflags & 0x3f),
				ntohs(tcphdr->tcpwindow),
				ntohs(tcphdr->tcpurg));
		data = (data + ((tcphdr->tcplen >> 4) * 4));
		Size -= ((tcphdr->tcplen >> 4) * 4);
	}
	else if (iphdr->ipproto == 17) {
		udphdr = (UDP_HDR *)data;
		printf("SrcPort %d DstPort %d Len %d\n",
				ntohs(udphdr->udpsourceport),
				ntohs(udphdr->udpdestport),
				ntohs(udphdr->udplen));
		data = (data + 8);
		Size -= 8;
	}
	int i;
	i = 0;
	int InstructionLen;
	for (;i < Size;i++) {
		if (data[i] < 0x20 || data[i] == 0xff) {
			printf(".");
		}
		else {
			printf("%c", data[i]);
		}
	}
	printf("\n");
}

