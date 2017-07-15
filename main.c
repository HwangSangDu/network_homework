#include "packet.h"
//eth.smac, eth.dmac / ip.sip, ip.dip / tcp.sport, tcp.dport / data

int main(int argc, char *argv[])
{
	Packet p;
	int ip_size , port_size;
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
		
		///*
		printf("Jacked a packet with length of [%d]\n", header.len);
		if (packet)//packet != NULL
		{
			ip_size = (packet[ETHSIZE] & 0x0f) << 2;
			port_size = packet[ETHSIZE + ip_size + 13] << 3;

			my_memcpy(p.eth[DESTINATION], packet, MACADDRSIZE);
			my_memcpy(p.eth[SOURCE], packet + MACADDRSIZE , MACADDRSIZE);
			my_memcpy(p.ip[SOURCE], packet + ETHSIZE + ip_size - IPADDRSIZE*2 , IPADDRSIZE);
			my_memcpy(p.ip[DESTINATION], packet + ETHSIZE + ip_size - IPADDRSIZE, IPADDRSIZE);
			my_memcpy(p.port[SOURCE], packet + ETHSIZE + ip_size, PORTNUMSIZE);
			my_memcpy(p.port[DESTINATION], packet + ETHSIZE + ip_size + PORTNUMSIZE, PORTNUMSIZE);
			my_memcpy(p.data , packet + ETHSIZE + ip_size + port_size , 15);
			printf("\n\n");
			printf("*********** Ethernet *****************\n");
			printf("%-15s" , "DESTINATION : ");
			str_to_hex_print(p.eth[DESTINATION] , MACADDRSIZE);
			printf("%-15s" , "SOURCE : ");
			str_to_hex_print(p.eth[SOURCE] , MACADDRSIZE);
			printf("*********** IP *****************\n");
			printf("%-15s" , "DESTINATION : ");
			str_to_hex_print(p.ip[DESTINATION] , IPADDRSIZE);
			printf("%-15s" , "SOURCE : ");
			str_to_hex_print(p.ip[SOURCE] , IPADDRSIZE);
			printf("*********** Port *****************\n");
			printf("%-15s" , "DESTINATION : ");
			str_to_hex_print(p.port[DESTINATION] , PORTNUMSIZE);
			printf("%-15s" , "SOURCE : ");
			str_to_hex_print(p.port[SOURCE] , PORTNUMSIZE);
			printf("%-15s" , "Data : ");
			str_to_hex_print(p.data , 15);
			printf("\n\n");

		}
		//*/
	}
	pcap_close(handle);
	return(0);
}

