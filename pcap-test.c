#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <stdbool.h>


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
};

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    };

    param->dev_ = argv[1];

    return true;
};

void printEthernet(const u_char* packet) {
    struct libnet_ethernet_hdr * ethernetHeader = (struct libnet_ethernet_hdr *) packet;
    printf("[Ethernet Header] \n");
    printf("\tsrc mac :\t");
    for(int i=0; i<6; i++) {
        printf("%02x ", ethernetHeader->ether_shost[i]);
    };
    printf("\n");
    printf("\tdst mac :\t");
    for(int i=0; i<6; i++) {
        printf("%02x ", ethernetHeader->ether_dhost[i]);
    };
    printf("\n");
}

void printIp(const u_char* packet) {
    struct libnet_ipv4_hdr * ipHeader = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
    printf("[IP Header] \n");

    printf("\tsrc ip :\t");

    for(int i=24; i>=0; i-=8) {
        printf("%d", (ntohl(ipHeader->ip_src.s_addr) >> i) & 0xff);
        if(i!=0) {
            printf(".");
        } else {
            printf("\n");
        }
    }
    printf("\n");


    printf("\tdst ip :\t");

    for(int i=24; i>=0; i-=8) {
        printf("%d", (ntohl(ipHeader->ip_dst.s_addr) >> i) & 0xff);
        if(i!=0) {
            printf(".");
        } else {
            printf("\n");
        }
    }


}

void printTcp(const u_char* packet) {
    struct libnet_tcp_hdr * tcpHeader = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
    printf("[TCP Header] \n");
    printf("\tsrc port :\t");
    printf("%u\n", ntohs(tcpHeader->th_sport));
    printf("\tdst port :\t");
    printf("%u\n", ntohs(tcpHeader->th_dport));
}

void printPayload(const u_char* packet) {
    const u_char * payload = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
    printf("[Payload] \n");
    printf("\thexadecimal value :\t");
    for(int i = 0; i < 8; i++) {
        printf("%02x ", *(payload + i));
    }
    printf("\n");
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

        printEthernet(packet);
        printIp(packet);
        printTcp(packet);
        printPayload(packet);
    }

    pcap_close(pcap);
}
