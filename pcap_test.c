 #include <pcap.h>
 #include <stdio.h>
 #include <string.h>
//eth.smac, eth.dmac / ip.sip, ip.dip / tcp.sport, tcp.dport / data
typedef struct  packet_address
{
	u_char eth[2][10];
	u_char* ip[2];
	u_char* port[2];
	u_char* data[2];
}Packet;
 int main(int argc, char *argv[])
 {
 	Packet p;
 	int i;
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

	while(1)
	{
		packet = pcap_next(handle, &header);
		/*
		if(packet){
			for (i = 0; i < 6; ++i)
				printf("%x" ,packet[i]);
			printf("\n");
		}
		//*/
		///*
		printf("Jacked a packet with length of [%d]\n", header.len);
		if(packet)//packet != NULL
		{
			strncpy(p.eth[0],packet ,6);
			for (i = 0; i < strlen(p.eth[0]); ++i)
				printf("%x",*(p.eth[0]));
			printf("\n");
		}
		//*/
		/* Print its length */
		
		/* And close the session */
		
	}
	pcap_close(handle);
	return(0);
 }