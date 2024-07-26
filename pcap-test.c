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

struct libnet_ethernet_hdr {
    u_int8_t  ether_dhost[6]; /* destination ethernet address */
    u_int8_t  ether_shost[6]; /* source ethernet address */
    u_int16_t ether_type;     /* protocol */
};

struct libnet_ipv4_hdr {
    u_int8_t ip_vhl;          /* version << 4 | header length >> 2 */
    u_int8_t ip_tos;          /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr {
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;         /* sequence number */
    u_int32_t th_ack;         /* acknowledgement number */
    u_int8_t th_offx2;        /* data offset, rsvd */
    u_int8_t th_flags;        /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac_address(const char* label, const u_int8_t* mac) {
    printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n", label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_address(const char* label, struct in_addr ip) {
    printf("%s %s\n", label, inet_ntoa(ip));
}

void print_tcp_port(const char* label, u_int16_t port) {
    printf("%s %d\n", label, ntohs(port));
}

void print_payload(const u_char* payload, int len) {
    printf("Payload: ");
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
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        print_mac_address("Src MAC:", eth_hdr->ether_shost);
        print_mac_address("Dst MAC:", eth_hdr->ether_dhost);

        if (ntohs(eth_hdr->ether_type) == 0x0800) { // IPv4
            struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
            print_ip_address("Src IP:", ip_hdr->ip_src);
            print_ip_address("Dst IP:", ip_hdr->ip_dst);

            int ip_header_len = (ip_hdr->ip_vhl & 0x0F) * 4;
            if (ip_hdr->ip_p == IPPROTO_TCP) {
                struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)((u_char*)ip_hdr + ip_header_len);
                print_tcp_port("Src Port:", tcp_hdr->th_sport);
                print_tcp_port("Dst Port:", tcp_hdr->th_dport);

                int tcp_header_len = ((tcp_hdr->th_offx2 & 0xF0) >> 4) * 4;
                const u_char* payload = (u_char*)tcp_hdr + tcp_header_len;
                int payload_len = ntohs(ip_hdr->ip_len) - (ip_header_len + tcp_header_len);
                print_payload(payload, payload_len);
            }
        }

        //printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(pcap);
    return 0;
}
