//dawson and Isaiah

#include<netinet/ip.h>
#include<stdio.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<string.h>
#include<stdlib.h>
#include "sniffer.h"

int InitRawSock(int proto){
	int raw_sock = socket(AF_INET , SOCK_RAW, proto);
	if(raw_sock < 0){
		//printf("error init raw socket: %s\n", strerror(errno));
		return -1;
	}
	return raw_sock;
}
int ipHeaderToFile(struct iphdr* hdr, FILE* write_file){
	//printf("in ip header print\n");
	fprintf(write_file, "\n===Header for IP===:\n");
	fprintf(write_file, "----Version= %d\n",(unsigned int)hdr->version);
	int len = (unsigned int)hdr->ihl;
	fprintf(write_file, "----Protocol= %d\n",(unsigned int)hdr->protocol);
	fprintf(write_file, "----Header size= %d\n",len);
	fprintf(write_file, "----ID= %d\n", ntohs(hdr->id));
	fprintf(write_file, "----Service= %d\n",(unsigned int)hdr->tos);
	fprintf(write_file, "----Checksum= %d\n",ntohs(hdr->check));
	fprintf(write_file, "----Length= %d\n", ntohs(hdr->tot_len));
	fprintf(write_file, "----TTL= %d\n",(unsigned int)hdr->ttl);
	return len;
	
}

void saveAndParsePack(unsigned char* pack, FILE* write_file, int pack_size){
	//printf("in save n parse\n");
	struct iphdr* hdr = (struct iphdr*)pack;
	int offset_IP = ipHeaderToFile(hdr, write_file);
	int proto = hdr->protocol;
	if(proto == 6){
		struct tcphdr * hdr_TCP = (struct tcphdr *)(offset_IP + pack); //points to address in mememory after ipheader and treats it as a tcp header struct pointer
		fprintf(write_file, "\n===Header for TCP===:\n");
		fprintf(write_file,"----Acknowledge Number= %u\n",ntohl(hdr_TCP->ack_seq));
		int offset_TCP = (unsigned int)hdr_TCP->doff*4;
		fprintf(write_file,"----Header Length in bytes= %d\n" ,offset_TCP);
		fprintf(write_file,"----Destination Port= %u\n",ntohs(hdr_TCP->dest));
		fprintf(write_file,"----Source Port= %u\n",ntohs(hdr_TCP->source));
		fprintf(write_file,"----Sequence Number= %u\n",ntohl(hdr_TCP->seq));
		fprintf(write_file,"----Window= %d\n",ntohs(hdr_TCP->window));
		fprintf(write_file,"----Checksum= %d\n",ntohs(hdr_TCP->check));
		fprintf(write_file,"----Urgent Pointer= %d\n",hdr_TCP->urg_ptr);
		fprintf(write_file,"----Ack flag= %d\n",(unsigned int)hdr_TCP->ack);
		fprintf(write_file,"----Urgent= %d\n",(unsigned int)hdr_TCP->urg);
		fprintf(write_file,"----Synchronise Flag= %d\n",(unsigned int)hdr_TCP->syn);
		fprintf(write_file,"----Push Flag=  %d\n",(unsigned int)hdr_TCP->psh);
		fprintf(write_file,"----Reset Flag= %d\n",(unsigned int)hdr_TCP->rst);
		fprintf(write_file,"----Finish Flag= %d\n",(unsigned int)hdr_TCP->fin);
			
		
		fprintf(write_file, "-xxxxx Raw hex of packet xxxxx-\n");
		unsigned int* byte;
		//int offset_len = offset_IP + offset_TCP;
		//int payload_len = pack_size - offset_len;
		for(int i = 0; i < pack_size; i++){
			byte = (unsigned int*)(pack + (i*4));
			fprintf(write_file, " %x", *byte);
			//printf("in raw loop\n");
			if(i%4 == 0) fprintf(write_file, "\n");
		}
	}
	else if(proto == 11){
		struct udphdr * hdr_UDP = (struct udphdr *)(offset_IP + pack); //points to address in mememory after ipheader and treats it as a udp header struct pointer
		fprintf(write_file, "\n===Header for UDP===:\n");
		fprintf(write_file,"----Checksum= %u\n",ntohs(hdr_UDP->check));
		fprintf(write_file,"----Destination Port= %u\n",ntohs(hdr_UDP->dest));
		fprintf(write_file,"----Source Port= %u\n",ntohs(hdr_UDP->source));
		fprintf(write_file,"----Packet length= %u\n",ntohs(hdr_UDP->len));
		
		
		fprintf(write_file, "-xxxxx Raw hex of packet xxxxx-\n");
		unsigned int* byte;
		for(int i = 0; i < pack_size; i++){
			byte = (unsigned int*)(pack + i*4);
			fprintf(write_file, " 0x%02X", *byte);
			//printf("in raw loop\n");
			if(i%4 == 0) fprintf(write_file, "\n");
		}
	}
	else{
		fprintf(write_file, "-xxxxx Raw hex of packet xxxxx-\n");
		unsigned int* byte;
		for(int i = 0; i < pack_size; i++){
			byte = (unsigned int*)(pack + i*4);
			fprintf(write_file, " 0x%02X", *byte);
			//printf("in raw loop\n");
			if(i%4 == 0) fprintf(write_file, "\n");
		}
	}
	return;
}

