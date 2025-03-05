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
#include <time.h>
#include <sqlite3.h>

#define PORT 80
#define THRESHOLD 100 // Jumlah request per detik untuk dianggap DoS
#define LOG_FILE "/var/log/dos_detection.log"
#define DB_FILE "dos_attacks.db"

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

void write_log(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str) - 1] = '\0'; // Hapus newline
        fprintf(log_file, "[%s] %s\n", time_str, message);
        fclose(log_file);
    }
}

void init_db() {
    sqlite3 *db;
    char *err_msg = 0;
    int rc = sqlite3_open(DB_FILE, &db);
    if (rc) {
        write_log("[ERROR] Failed to open database.");
        return;
    }
    
    char *sql = "CREATE TABLE IF NOT EXISTS attack_logs ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ip TEXT,"
                "timestamp TEXT"
                ");";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        write_log("[ERROR] Failed to create table.");
        sqlite3_free(err_msg);
    }
    sqlite3_close(db);
}

void log_attack_to_db(const char *ip) {
    sqlite3 *db;
    char *err_msg = 0;
    int rc = sqlite3_open(DB_FILE, &db);
    if (rc) {
        write_log("[ERROR] Failed to open database for logging.");
        return;
    }
    
    char sql[200];
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';
    snprintf(sql, sizeof(sql), "INSERT INTO attack_logs (ip, timestamp) VALUES ('%s', '%s');", ip, time_str);
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        write_log("[ERROR] Failed to insert attack log.");
        sqlite3_free(err_msg);
    }
    sqlite3_close(db);
}

void block_ip(const char *ip) {
    char command[100];
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip);
    system(command);
    
    char log_message[200];
    snprintf(log_message, sizeof(log_message), "[ALERT] IP %s blocked due to suspected DoS attack.", ip);
    write_log(log_message);
    log_attack_to_db(ip);
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
                char log_message[200];
                snprintf(log_message, sizeof(log_message), "[ALERT] Potential DoS attack detected from %s", inet_ntoa(ip_header->ip_src));
                write_log(log_message);
                block_ip(inet_ntoa(ip_header->ip_src));
            }
            request_count = 0;
            last_time = current_time;
        }
    }
}

int main() {
    daemonize();
    write_log("[INFO] DoS detection service started.");
    init_db();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        write_log("[ERROR] Failed to open network interface.");
        exit(EXIT_FAILURE);
    }
    
    struct bpf_program fp;
    char filter_exp[] = "tcp dst port 80";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        write_log("[ERROR] Failed to compile filter.");
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        write_log("[ERROR] Failed to set filter.");
        exit(EXIT_FAILURE);
    }
    
    write_log("[INFO] Monitoring traffic on port 80.");
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
