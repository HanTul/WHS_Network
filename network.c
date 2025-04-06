#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    unsigned int ip_hdr_len = ip->iph_ihl * 4;
    unsigned int ip_total_len = ntohs(ip->iph_len);

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_hdr_len);
    unsigned int tcp_hdr_len = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;
    unsigned int payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
    const u_char *payload = (u_char *)tcp + tcp_hdr_len;

    printf("\n=== TCP Packet ===\n");
    printf("[Ethernet Header]\n");
    printf(" src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf(" dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("[IP Header]\n");
    printf(" src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf(" dst IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("[TCP Header]\n");
    printf(" src Port: %u\n", ntohs(tcp->tcp_sport));
    printf(" dst Port: %u\n", ntohs(tcp->tcp_dport));
    
    if (payload_len > 0) {
        printf("[TCP Body] (length = %u bytes):\n", payload_len);
        fwrite(payload, 1, payload_len, stdout);
        printf("\n");
    } else {
        printf("[TCP Body] is empty.\n");
    }

    printf("=============================\n");
}


int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }

    printf("=== Sniffing on TCP ===\n");

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}
