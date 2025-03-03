#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>

#define PORT 80
#define THRESHOLD 100 // Jumlah request per detik untuk dianggap DoS

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    umask(0);
    setsid();
    if (chdir("/") < 0) exit(EXIT_FAILURE);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void block_ip(const char *ip) {
    char command[100];
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip);
    system(command);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int request_count = 0;
    static time_t last_time = 0;
    time_t current_time = time(NULL);
    
    if (last_time == 0) last_time = current_time;
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    
    if (ntohs(tcp_header->th_dport) == PORT) {
        request_count++;
        if (current_time > last_time) {
            if (request_count > THRESHOLD) {
                printf("[ALERT] Potential DoS attack detected from %s\n", inet_ntoa(ip_header->ip_src));
                block_ip(inet_ntoa(ip_header->ip_src));
            }
            request_count = 0;
            last_time = current_time;
        }
    }
}

int main() {
    daemonize();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        exit(EXIT_FAILURE);
    }
    
    struct bpf_program fp;
    char filter_exp[] = "tcp dst port 80";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        exit(EXIT_FAILURE);
    }
    
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
