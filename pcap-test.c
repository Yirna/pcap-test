#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

struct eth_hdr {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct ipv4_hdr {
    uint8_t header_len : 4;
    uint8_t version : 4;
    uint8_t type_of_service;
    uint16_t total_packet_len;
    uint16_t fragment_identification;
    uint16_t flags;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t reserved : 4;
    uint8_t header_len : 4;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];  
    return true;
}

void print_mac_address(const char* label, const uint8_t* mac) {
    printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n", label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_address(const char* label, const uint8_t* ip) {
    printf("%s %d.%d.%d.%d\n", label, ip[0], ip[1], ip[2], ip[3]);
}

void print_tcp_port(const char* label, uint16_t port) {
    printf("%s %d\n", label, ntohs(port));
}

void print_payload(const uint8_t* payload, int len) {
    printf("Payload (%d bytes): ", len);
    for (int i = 0; i < len && i < 20; ++i) {
        printf("%02x ", payload[i]);
    }
    if (len > 20) {
        printf("...");
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
        const uint8_t* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct eth_hdr* eth_hdr = (struct eth_hdr*)packet;
        print_mac_address("Src MAC:", eth_hdr->src_mac);
        print_mac_address("Dst MAC:", eth_hdr->dst_mac);

        if (ntohs(eth_hdr->type) == 0x0800) { // IPv4
            struct ipv4_hdr* ip_hdr = (struct ipv4_hdr*)(packet + sizeof(struct eth_hdr));
            print_ip_address("Src IP:", ip_hdr->src_ip);
            print_ip_address("Dst IP:", ip_hdr->dst_ip);

            int ip_header_len = ip_hdr->header_len * 4;
            if (ip_hdr->protocol == IPPROTO_TCP) {
                struct tcp_hdr* tcp_hdr = (struct tcp_hdr*)((uint8_t*)ip_hdr + ip_header_len);
                print_tcp_port("Src Port:", tcp_hdr->src_port);
                print_tcp_port("Dst Port:", tcp_hdr->dst_port);

                int tcp_header_len = tcp_hdr->header_len * 4;
                int eth_header_len = 14;
                const uint8_t* payload = (uint8_t*)tcp_hdr + tcp_header_len;
                int total_len = ntohs(ip_hdr->total_packet_len);
                int header_len = ip_header_len + tcp_header_len;                
                int payload_len = total_len - header_len;

                if (payload_len > 0) {
                    print_payload(payload, payload_len);
                } else {
                    printf("No payload\n");
                }
            }
        }
    }

    pcap_close(pcap);
    return 0;
}
