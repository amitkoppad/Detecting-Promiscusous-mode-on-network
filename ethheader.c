#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include"myheader.h"

#define MAC0	0xff
#define MAC1	0x00
#define MAC2	0x00
#define MAC3	0x00
#define MAC4	0x00
#define MAC5	0x00

//08:00:27:87:7d:83

#define DEFAULT_IF	"enp0s3"
#define BUF_SIZ		1024


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



int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct ipheader *ip = (struct ipheader *) (sendbuf + sizeof(struct ether_header));
	struct icmpheader *icmp = (struct icmpheader *) 
                             (sendbuf + sizeof(struct ether_header) + sizeof(struct ipheader));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
	
	/* Get interface name to send the packet on */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");


	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = MAC0;
	eh->ether_dhost[1] = MAC1;
	eh->ether_dhost[2] = MAC2;
	eh->ether_dhost[3] = MAC3;
	eh->ether_dhost[4] = MAC4;
	eh->ether_dhost[5] = MAC5;

	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);

	/* Construct ICMP header */

  	icmp->icmp_type = 8; /* ICMP Type: 8 is request, 0 is reply. */

 	 /* Calculate the checksum for integrity */
	icmp->icmp_chksum = 0;
	icmp->icmp_chksum = in_cksum((unsigned short *)icmp, 
                                 sizeof(struct icmpheader));

	/* Construct IP header */
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 64;
	ip->iph_sourceip.s_addr = inet_addr("10.0.2.6");
	ip->iph_destip.s_addr = inet_addr("10.0.2.5");
	ip->iph_protocol = IPPROTO_ICMP; 
	ip->iph_len = htons(sizeof(struct ipheader) + 
                       sizeof(struct icmpheader));

	ip->iph_chksum = in_cksum((unsigned short *)ip,
				sizeof(struct ipheader));	

        int total_len = (sizeof(struct ether_header) + sizeof(struct ipheader) + 
                       sizeof(struct icmpheader));


	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;

	/* Destination MAC */
	socket_address.sll_addr[0] = MAC0;
	socket_address.sll_addr[1] = MAC1;
	socket_address.sll_addr[2] = MAC2;
	socket_address.sll_addr[3] = MAC3;
	socket_address.sll_addr[4] = MAC4;
	socket_address.sll_addr[5] = MAC5;

	/* Send packet */
	if (sendto(sockfd, sendbuf, total_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");

	return 0;
}
