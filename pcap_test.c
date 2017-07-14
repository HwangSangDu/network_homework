#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//eth.smac, eth.dmac / ip.sip, ip.dip / tcp.sport, tcp.dport / data
typedef struct  packet_address
{
	///*
	u_char* eth[2];
	u_char* ip[2];
	u_char* port[2];
	u_char* data[2];
	//*/
	/*
	int eth[2];//start ,end
	int ip[2];
	int port[2];
	int data[2];
	//*/
}Packet;

u_char* my_strncpy(u_char* d, const u_char* s, int len)
{
	u_int i;
	d = malloc(sizeof(u_char) * (len + 1));
	for (i = 0; i < len; ++i)
		d[i] = s[i];
	d[len] = '\0';
	return d;
}
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
			//my_strncpy(p.eth[0] , packet , 6);
			//memcpy(p.eth[0], packet, 6);

			for (i = 0; i < 6; ++i)
				printf("%02x", p.eth[0][i]);
			printf("\n");
		}
		//*/
	}
	pcap_close(handle);
	return(0);
}

