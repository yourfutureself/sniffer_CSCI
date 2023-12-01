//dawson and Isaiah
#ifndef HEADER_FILE
#define HEADER_FILE
#define MAX 65535
#include<netinet/ip.h>
#include<stdio.h>
   
int InitRawSock(int proto);
int ipHeaderToFile(struct iphdr* hdr, FILE* write_file);
void saveAndParsePack(unsigned char* pack, FILE* write_file, int pack_size);

#endif
