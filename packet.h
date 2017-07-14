#ifndef __PACKET_H__
#define __PACKET_H__

#include "common.h"

#define DESTINATION 0
#define SOURCE 1
#define MACADDRSIZE 6
#define IPADDRSIZE 4
#define PORTNUMSIZE 2
#define ETHSIZE 14
#define IPSIZE 20

typedef struct  packet_address
{
	///*
	u_char eth[2][MACADDRSIZE];
	u_char ip[2][IPADDRSIZE];
	u_char port[2][PORTNUMSIZE];
	u_char data[2];
	//*/
	/*
	int eth[2];//start ,end
	int ip[2];
	int port[2];
	int data[2];
	//*/
}Packet;

u_char* my_memcpy(u_char* d, const u_char* s, int len);
void str_to_hex_print(u_char* str , int len);
#endif