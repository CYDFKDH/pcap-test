#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

typedef struct
{
    uint8_t  ether_dhost[6];/* destination ethernet address */
    uint8_t  ether_shost[6];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
}libnet_ethernet_hdr;

typedef struct
{
    uint8_t ip_v;       /* version */
    uint8_t ip_tos;       /* type of service */
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    uint32_t shost_Addr;
    uint32_t dhost_Addr;
}libnet_ipv4_hdr;

typedef struct
{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */
    uint8_t th_off;        /* data offset */
    uint8_t  th_flags;       /* control flags */
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
}libnet_tcp_hdr;

#pragma pack(1)
typedef struct{
    libnet_ethernet_hdr ethernet_hdr;
    libnet_ipv4_hdr ipv4_hdr;
    libnet_tcp_hdr tcp_hdr;
    uint8_t    data[20];
}Packet;
#pragma unpack

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		Packet *pac = (Packet*)packet;
		
		if((pac->ipv4_hdr.ip_p) == 6){
		
		    printf("src Mac = ");
		    for(int i=0;i<5;i++){
		        printf("%02x:", pac->ethernet_hdr.ether_dhost[i]);
		    }
		    printf("%02x\n", pac->ethernet_hdr.ether_dhost[5]);
		    
		    printf("dst Mac = ");
		    for(int i=0;i<5;i++){
		        printf("%02x:", pac->ethernet_hdr.ether_shost[i]);
		    }
		    printf("%02x\n", pac->ethernet_hdr.ether_shost[5]);
		    
		    printf("src Ip = ");
		    uint32_t s_ip = ntohl(pac->ipv4_hdr.shost_Addr);
		    for(int i=3;i>0;i--){
		        printf("%u.",(s_ip>>(i*8))&0xFF);
		    }
		    printf("%u\n",(s_ip&0xFF));
		    
		    printf("dst Ip = ");
		    uint32_t d_ip = ntohl(pac->ipv4_hdr.dhost_Addr);
		    for(int i=3;i>0;i--){
		        printf("%u.",(d_ip>>(i*8))&0xFF);
		    }
		    printf("%u\n",(d_ip&0xFF));
		    
		    printf("src port = %u\n",pac->tcp_hdr.th_sport);
		    printf("src port = %u\n",pac->tcp_hdr.th_dport);
		    
		    printf("Data =\n");
		    for(int i=0;i<20;i++){
		        printf("%02X ", pac->data[i]);
		        if(i==15) printf("\n");
		    }
		    printf("\n");
		    
		    
		}
	}

	pcap_close(pcap);
}


