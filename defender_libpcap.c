#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *iph = (struct ip *)(packet + 14); // Ethernet header = 14 bytes
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);

    if (ntohs(tcph->dest) == 80) { // Memantau port 80 (HTTP)
        printf("Permintaan HTTP dari IP: %s\n", inet_ntoa(iph->ip_src));
        // Di sini bisa ditambahkan logika blokir IP jika request berlebihan
    }
}

int main() {
    char *device = "eth0"; // Ganti dengan interface jaringan VPS-mu jika berbeda
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Tidak bisa membuka perangkat: %s\n", errbuf);
        return 2;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp port 80"; // Filter hanya untuk TCP port 80
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Gagal kompilasi filter\n");
        return 2;
    }
    pcap_setfilter(handle, &fp);

    printf("Memantau lalu lintas HTTP di background...\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}