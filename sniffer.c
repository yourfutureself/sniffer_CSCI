//dawson and Isaiah

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
//for packet parsing:
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>


#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/ip.h>

#include "sniffer.h"





int main(int argc, char *argv[]){
	unsigned char* buff = (unsigned char*)malloc(MAX);
	memset(buff, 0, sizeof(buff));
	struct sockaddr* blank_add;
	int size_storage = sizeof blank_add;
	int protocol = atoi(argv[2]);
	int raw_sock = InitRawSock(protocol);
	if( raw_sock == -1) return raw_sock; 
	FILE *write_file;
	char name[17];
	for(int i = 0; i < atoi(argv[1]); i++){
		snprintf(name, 17, "packet%d.txt", i);
		write_file=fopen(name,"w");
		if(write_file==NULL){
			printf("cannot create file.");
			return -1;
		}
		int byte_size = recvfrom(raw_sock , buff , 65536 , 0 , blank_add , &size_storage);
		saveAndParsePack(buff, write_file, byte_size);
		fclose(write_file);
	};
	
	close(raw_sock);
	printf("done\n");
	return 0;
}
/*
int InitRawSock(int proto){
	int raw_sock = socket(AF_INET , SOCK_RAW, proto);
	if(raw_sock < 0){
		printf("error init raw socket: %s\n", strerror( errno ));
		return -1;
	}
	return raw_sock;
}


