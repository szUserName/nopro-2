#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#define LINE_LEN 16

#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib , "wpcap.lib") //For winpcap

// gcc npa.c -o npa.exe -lwpcap -lws2_32
// npa -n \Device\NPF_{816E3E0B-E521-4F36-A79C-F9178C83055C}

main(int argc, char **argv) {
    
    pcap_if_t *alldevs, *d;
    pcap_t *fp;
    u_int inum, i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    struct pcap_pkthdr *header;
    u_char *pkt_data;

    printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
    printf("\t Usage: pktdump_ex [-n adapter] | [-f file_name]\n\n");

    if(argc < 3){
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {  /* The user didn't provide a packet source: Retrieve the device list */
            fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
            exit(1);
        }
        
        /* Print the list */
        for(d=alldevs; d; d=d->next) {
            printf("%d. %s", ++i, d->name);
            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }
        
        if(i==0) {
            printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
            return -1;
        }
        
        printf("Enter the interface number (1-%d):",i);
        scanf("%d", &inum);
        
        if(inum < 1 || inum > i) {
            printf("\nInterface number out of range.\n");
            pcap_freealldevs(alldevs); /* Free the device list */
            return -1;
        }
        for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++); /* Jump to the selected adapter */
        if ( (fp= pcap_open_live(d->name, 100, 1, 20, errbuf) ) == NULL) { /* Open the device */
            fprintf(stderr,"\nError opening adapter\n");
            return -1;
        }
    }
    else {
        
        
        switch (argv[1] [1]) { /* The user provided a packet source: open it */
            
        case 'n':
            { /* Open a physical device */
                if ( (fp= pcap_open_live(argv[2], 100, 1, 20, errbuf) ) == NULL) {
                    fprintf(stderr,"\nError opening adapter\n");
                    return -1;
                }
            };
            break;
            
        case 'f':
            { /* Open a capture file */
                if ( (fp = pcap_open_offline(argv[2], errbuf) ) == NULL) {
                    fprintf(stderr,"\nError opening dump file\n");
                    return -1;
                }
            };
            break;
        }
    }
    while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0) { /* Read the packets */

        if(res == 0)
            /* Timeout elapsed */
            continue;
        printf("tv_sec %ld: tv_usec %ld (len %ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len); /* print pkt timestamp and pkt len */
        
        /* Print the packet */
        for (i=1; (i < header->caplen + 1 ) ; i++) {
            printf("%.2x ", pkt_data[i-1]);
            if ( (i % LINE_LEN) == 0) printf("\n");
        }
        
        printf("\n\n");     
    }

    if(res == -1) {
        printf("Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}