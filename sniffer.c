//dawson
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <errno.h>
//for packet parsing:
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>

#include<sys/socket.h>
#include<arpa/inet.h>

#define MAX 65535
   
int InitRawSock(){
	int raw_sock = socket(AF_INET , SOCK_RAW, IPPROTO_TCP);
	if(raw_sock < 0){
		printf("error init raw socket: %s\n", strerror( errno ));
		return -1;
	}
	return raw_sock;
}

void saveAndParsePack(int proto, struct iphdr* pack, FILE* write_file){
	
	if(proto == 6){
		fprintf(write_file, "\nHeader:\n");
		fprintf(write_file, "----Version:%d\n",(unsigned int)pack->version);
		fprintf(write_file, "----Header size: %d",(unsigned int)pack->ihl);
		fprintf(write_file, "----Service: %d\n",(unsigned int)pack->tos);
		fprintf(write_file, "----Service: %d\n", ntohs(pack->tot_len));
		fprintf(write_file, "----ID: %d\n", ntohs(pack->id));
		fprintf(write_file, "----TTL: %d\n",(unsigned int)pack->ttl);
		fprintf(write_file, "----Protocol : %d\n",(unsigned int)pack->protocol);
		fprintf(write_file, "----Checksum : %d\n",ntohs(pack->check));
		//fprintf(write_file, "----Source: %s\n",inet_ntoa(source.sin_addr));
		//fprintf(write_file, "----Destination: %s\n",inet_ntoa(dest.sin_addr));
	}
	return;
}

int main(int argc, char *argv[]){
	struct iphdr* buff = (struct iphdr*)malloc(MAX);
	memset(buff, 0, sizeof(buff));
	struct sockaddr* blank_add;
	int size_storage = sizeof blank_add;
	int raw_sock = InitRawSock();
	if( raw_sock == -1) return raw_sock; 
	FILE *write_file;
	char name[17];
	for(int i = 0; i < argv[1][0]; i++){
		snprintf(name, 17, "write_file%d.txt", i);
		write_file=fopen(name,"w");
		if(write_file==NULL){
			printf("cannot create file.");
			return -1;
		}
		int byte_size = recvfrom(raw_sock , buff , 65536 , 0 , blank_add , &size_storage);
		saveAndParsePack(buff->protocol, buff, write_file);
		fclose(write_file);
	};
	
	close(raw_sock);
	printf("done\n");
	return 0;
}

