#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet_data) {
    struct ether_header *eth_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    u_int16_t ether_type;

    // Get the Ethernet header
    eth_header = (struct ether_header *) packet_data;
    ether_type = ntohs(eth_header->ether_type);

    // Check if the Ethernet frame contains an IP packet
    if (ether_type == ETHERTYPE_IP) {
        // Get the IP header
        ip_header = (struct iphdr *)(packet_data + sizeof(struct ether_header));

        // Check if the IP packet contains a TCP segment
        if (ip_header->protocol == IPPROTO_TCP) {
            // Get the TCP header
            tcp_header = (struct tcphdr *)(packet_data + sizeof(struct ether_header) + sizeof(struct iphdr));

            // Print the source and destination IP addresses and port numbers
            printf("%s:%d -> %s:%d\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr), ntohs(tcp_header->source),
                   inet_ntoa(*(struct in_addr *)&ip_header->daddr), ntohs(tcp_header->dest));
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net, mask;

    // Find the network interface and its netmask
    if (pcap_lookupnet("eth0", &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device eth0\n");
        net = 0;
        mask = 0;
    }

    // Open the network interface in promiscuous mode
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device eth0: %s\n", errbuf);
        return 1;
    }

    // Compile and apply the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Start capturing packets
    printf("Capturing packets on eth0...\n");
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
