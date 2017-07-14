#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//eth.smac, eth.dmac / ip.sip, ip.dip / tcp.sport, tcp.dport / data
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


/*
u_char* my_strncpy(u_char* d, const u_char* s, int len)
{
u_int i;
d = malloc(sizeof(u_char) * (len + 1));
for (i = 0; i < len; ++i)
d[i] = s[i];
d[len] = '\0';
return d;
}
//*/

///*
u_char* my_memcpy(u_char* d, const u_char* s, int len)
{
	int i;
	//d = (u_char *)malloc(sizeof(u_char) * (len + 1));
	for (i = 0; i < len; ++i)
		d[i] = s[i];
	return d;
}
//*/

void str_to_hex_print(u_char* str)
{
	int i;
	printf("%d\n",sizeof(str));
	for (i = 0; i < sizeof(str) / sizeof(u_char) ; i++)
		printf("%02x", str[i]);
	printf("\n");
}
	//for (i = 0; i < MACADDRSIZE; i++)
	//{

	//}
	//for (i = 0; i < IPADDRSIZE; i++)
	//{

	//}
	//for (i = 0; i < IPADDRSIZE; i++)
	//{

	//}
	//for (i = 0; i < PORTNUMSIZE; i++)
	//{

	//}
	//for (i = 0; i < PORTNUMSIZE; i++)
	//{

	//}

int main(int argc, char *argv[])
{
	Packet p;
	u_int i;
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

								/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */

	while (1)
	{
		packet = pcap_next(handle, &header);
		/*
		printf("Jacked a packet with length of [%d]\n", header.len);
		if(packet){
		for (i = 0; i < 6; ++i)
		printf("%02x" ,packet[i]);
		printf("\n");
		}

		if(packet){
		for (i = 6; i < 12; ++i)
		printf("%02x" ,packet[i]);
		printf("\n");
		}

		if(packet){
		for (i = 26; i < 30; ++i)
		printf("%02x" ,packet[i]);
		printf("\n");
		}

		if(packet){
		for (i = 30; i < 34; ++i)
		printf("%02x" ,packet[i]);
		printf("\n");
		}

		if(packet){
		for (i = 34; i < 36; ++i)
		printf("%02x" ,packet[i]);
		printf("\n");
		}
		if(packet){
		for (i = 36; i < 38; ++i)
		printf("%02x" ,packet[i]);
		printf("\n");
		}
		//*/
		///*
		printf("Jacked a packet with length of [%d]\n", header.len);
		if (packet)//packet != NULL
		{
			my_memcpy(p.eth[DESTINATION], packet, MACADDRSIZE);
			my_memcpy(p.eth[SOURCE], packet + MACADDRSIZE , MACADDRSIZE);
			my_memcpy(p.ip[SOURCE], packet + ETHSIZE , IPSIZE);
			my_memcpy(p.ip[DESTINATION], packet + ETHSIZE + IPSIZE, IPSIZE);
			my_memcpy(p.port[SOURCE], packet + ETHSIZE + IPSIZE, PORTNUMSIZE);
			my_memcpy(p.port[DESTINATION], packet + ETHSIZE + IPSIZE + PORTNUMSIZE, PORTNUMSIZE);
			printf("\n\n");
			printf("*********** Ethernet *****************\n");
			printf("%-15s" , "DESTINATION : ");
			str_to_hex_print(p.eth[DESTINATION]);
			printf("%-15s" , "SOURCE : ");
			str_to_hex_print(p.eth[SOURCE]);
			printf("*********** IP *****************\n");
			printf("%-15s" , "DESTINATION : ");
			str_to_hex_print(p.ip[DESTINATION]);
			printf("%-15s" , "SOURCE : ");
			str_to_hex_print(p.ip[SOURCE]);
			printf("*********** Port *****************\n");
			printf("%-15s" , "DESTINATION : ");
			str_to_hex_print(p.port[DESTINATION]);
			printf("%-15s" , "SOURCE : ");
			str_to_hex_print(p.port[SOURCE]);
			printf("\n\n");
		}
		//*/
	}
	pcap_close(handle);
	return(0);
}

