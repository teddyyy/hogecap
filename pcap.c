#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "analyze.h"

int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
	struct ifreq ifreq;
	struct sockaddr_ll sa;
	int sock;

	if (ipOnly) {
		if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
			perror("socket");
			return -1;
		}
	} else {
		if((sock = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_ALL))) < 0) {
			perror("socket");
			return -1;
		}
	} 

	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
	if (ioctl(sock, SIOCGIFINDEX, &ifreq) < 0) {
		perror("ioctl");
		close(sock);
		return -1;
	}

	sa.sll_family=PF_PACKET;
	if(ipOnly) {
		sa.sll_protocol = htons(ETH_P_IP);
	} else {
		sa.sll_protocol = htons(ETH_P_ALL);
	}

	sa.sll_ifindex = ifreq.ifr_ifindex;
	if(bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		perror("bind");
		close(sock);
		return -1;
	}

	if(promiscFlag) {
		if(ioctl(sock, SIOCGIFFLAGS, &ifreq) < 0) {
			perror("ioctl");
			close(sock);
			return -1;
		}
		ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC; 
		if(ioctl(sock, SIOCGIFFLAGS, &ifreq) < 0) {
			perror("ioctl");
			close(sock);
			return -1;
		}
	}
	
	return sock;
}

int main(int argc, char *argv[], char *envp[])
{
	int sock, size;
	u_char buf[65535];

	if(argc <= 1) {
		fprintf(stderr,"./pcap device_name\n");
		return 1;
	}

	if ((sock = InitRawSocket(argv[1], 0, 0)) == -1) {
		fprintf(stderr,"InitRawSocket:error:%s\n",argv[1]);
		return -1;
	}

	while(1) {
		if((size = read(sock, buf, sizeof(buf))) <= 0){
			perror("read");
		} else {
			AnalyzePacket(buf,size);
		}
	}

	close(sock);

	return 0;
}
