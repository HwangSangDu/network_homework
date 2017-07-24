#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <fcntl.h>
//#include <linux/ip.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

struct tcp_header
{
        u_short source_port;
        u_short dest_port;
        uint32_t sequence;
        uint32_t acknowledge;
        u_char ns:1;
        u_char reserved_part1:3;
        u_char data_offset:4;
        u_char fin:1;
        u_char syn:1;
        u_char rst:1;
        u_char psh:1;
        u_char ack:1;
        u_char urg:1;
        u_char ecn:1;
        u_char cwr:1;
        u_short window;
        u_short checksum;
        u_short urgent_pointer;
};


#endif