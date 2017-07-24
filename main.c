#include "packet.h"
//eth.smac, eth.dmac / ip.sip, ip.dip / tcp.sport, tcp.dport / data

int main(int argc, char *argv[])
{

	uint32_t flag , i;
	uint32_t ip_size , port_size;
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char *filter_exp;	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr* header;	/* The header that pcap gives us */
	struct ethhdr *ethhdr; 
	struct ip *iphdr; 
	struct tcp_header *tcphdr;
	const u_char *packet;		/* The actual packet */
	const u_char *temp;
	u_char dst_buf[32];
	u_char src_buf[32];
	//default 값
	if(argc < 2){
		printf("default value\n");
		filter_exp = "port 80";
		//strncpy(filter_exp, "port 80",strlen("port 80"));
	}

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
	for (i = 1; i < argc; ++i)
	{
		//filter_exp = argv[i];
		strncpy(filter_exp,argv[i],strlen(argv[i]));
		///*
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		//*/
	}
	/* Grab a packet */
	//https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut4.html 참조
	while ((flag = pcap_next_ex(handle, &header,&packet)) >= 0)
	{
		///* 수정 소스
		if(!flag)//flag == 0 (timeout)d
			continue;
		//Mac 주소
		printf("Jacked a packet with length of [%d`]\n", header->len);
		temp = packet;
		ethhdr = (struct ethhdr *) temp; 
		printf("DEST MAC=%s\n",ether_ntoa((struct ether_addr *) ethhdr->h_dest));
		printf("SRC  MAC=%s\n",ether_ntoa((struct ether_addr *) ethhdr->h_source));
		printf("PROTOCOL=%04x\n",ntohs(ethhdr->h_proto));
		//ip주소


		temp = packet + 14;
		iphdr =(struct ip *) temp; 
		//ip타입 아니면 pass
		if(iphdr->ip_p == 0x0800)
			continue;

		///*

		//printf("SRC  IP=%s\n",inet_ntoa(iphdr-> ip_src));
		//printf("DEST IP=%s\n",inet_ntoa(iphdr-> ip_dst));
		/* ntoa --> ntop */

		inet_ntop(AF_INET, &(iphdr-> ip_src) , src_buf , sizeof(src_buf));
		inet_ntop(AF_INET, &(iphdr-> ip_dst) , dst_buf , sizeof(dst_buf));
		printf("SRC  IP=%s\n",src_buf);
		printf("DEST IP=%s\n",dst_buf); 


		printf("PROTOCOL = %d\n", iphdr->ip_p);
		temp = packet + 14 + (iphdr->ip_hl << 2);
		//*/

		/*
		if(iphdr->protocol == 0x0800)
			continue;
		printf("SRC  IP=%x\n",ntohl(iphdr->saddr));
		printf("DEST IP=%x\n",ntohl(iphdr->daddr));
		printf("PROTOCOL = %d\n", iphdr->protocol);
		temp = packet + 14 + (iphdr->ihl << 2);
		//*/
		
		tcphdr = (struct tcp_header *)temp;
		printf("SRC  PORT=%d\n",ntohs(tcphdr->source_port));
		printf("DEST PORT=%d\n",ntohs(tcphdr->dest_port));

		
		printf("\n");

	}
	pcap_close(handle);
	return(0);
}

