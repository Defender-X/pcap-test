#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> // for ETH_P_IP
#include <netinet/ip.h>       // for struct ip
#include <netinet/tcp.h>      // for struct tcphdr

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

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac_address(u_char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_data(const u_char* data, int len) {
    int i;
    for(i = 0; i < len && i < 20; i++) { // Print only up to 20 bytes
        printf("%02x ", data[i]);
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

        struct ether_header* eth_header = (struct ether_header*)packet;
        if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) { // Check if it's an IP packet
            struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
            if(ip_header->ip_p == IPPROTO_TCP) { // Check if it's a TCP packet
                struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

                // Print MAC addresses

                printf("Src MAC: ");
                print_mac_address(eth_header->ether_shost);

                printf(", Dst MAC: ");
                print_mac_address(eth_header->ether_dhost);
                printf("\n");

                // Print IP addresses

                printf("Src IP: %s, ", inet_ntoa(ip_header->ip_src));
                printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

                // Print TCP ports

                printf("TCP Src Port: %d, ", ntohs(tcp_header->th_sport));
                printf("TCP Dst Port: %d\n", ntohs(tcp_header->th_dport));

                // Print Payload

                const u_char* payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
                int payload_len = ntohs(ip_header->ip_len) -
                                  - (sizeof(struct ip) + sizeof(struct tcphdr));

                printf("Payload (hexadecimal up to 20 bytes): ");
                print_data(payload, payload_len);
                printf("\n");
            }
        }
        //printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(pcap);
    return 0;
}
