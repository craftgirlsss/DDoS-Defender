#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT 80
#define MAX_REQUESTS 100
#define TIME_WINDOW 10 // Detik

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int request_count;
    time_t start_time;
} IpTracker;

IpTracker tracker[100];
int tracker_count = 0;

void block_ip(const char *ip) {
    char command[100];
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip);
    system(command);
    printf("IP %s telah diblokir karena permintaan berlebihan.\n", ip);
}

int find_ip(const char *ip) {
    for (int i = 0; i < tracker_count; i++) {
        if (strcmp(tracker[i].ip, ip) == 0) return i;
    }
    return -1;
}

void track_request(const char *ip) {
    time_t now = time(NULL);
    int idx = find_ip(ip);
    if (idx == -1) {
        strcpy(tracker[tracker_count].ip, ip);
        tracker[tracker_count].request_count = 1;
        tracker[tracker_count].start_time = now;
        tracker_count++;
    } else {
        if (now - tracker[idx].start_time <= TIME_WINDOW) {
            tracker[idx].request_count++;
            if (tracker[idx].request_count > MAX_REQUESTS) {
                block_ip(ip);
            }
        } else {
            tracker[idx].request_count = 1;
            tracker[idx].start_time = now;
        }
    }
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket gagal");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind gagal");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 10) < 0) {
        perror("Listen gagal");
        exit(EXIT_FAILURE);
    }
    printf("Memantau koneksi di port %d...\n", PORT);

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            perror("Accept gagal");
            continue;
        }
        char *ip = inet_ntoa(address.sin_addr);
        printf("Permintaan dari IP: %s\n", ip);
        track_request(ip);
        close(new_socket);
    }

    return 0;
}
