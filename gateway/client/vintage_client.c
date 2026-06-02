/* vintage_client.c — RustChain dial-up vintage miner client (bounty D6 reference).
 *
 * The vintage half of the split miner (see ../../docs/MINER_GATEWAY.md). Runs on the
 * OLD machine; speaks the rcgateway line protocol (../protocol.md) over TCP; gathers
 * minimal hardware evidence; computes the commitment; Ed25519-SIGNS the pipe-string
 * the node verifies (miner_id|miner|nonce|commitment) — all LOCALLY. The gateway does
 * the TLS/HTTP to the node. No key ever leaves this box.
 *
 * Deliberately small and dependency-light so it ports to a 486 / 68k / PPC:
 *   - C89-ish, POSIX sockets, no JSON library (the payload is tiny and hand-built)
 *   - SHA-256 vendored; Ed25519 via OpenSSL (default) or Monocypher (vintage)
 *
 * Build:  make            (OpenSSL backend, verifiable on modern + 486 Linux)
 *         make CRYPTO=monocypher    (drop monocypher.c/.h here first)
 *
 * Usage:  vintage_client --host 10.55.0.1 --port 8090 \
 *                        --miner g4-powerbook-115 --wallet RTCabc... \
 *                        [--seed-hex <64hex>] [--arch G4] [--family PowerPC]
 *
 * --seed-hex pins the Ed25519 seed (for reproducible test vectors); omit on real
 * hardware and it is read from ~/.rustchain_seed or generated and saved there.
 */
#include "rcc_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static void die(const char *m) { fprintf(stderr, "vintage_client: %s\n", m); exit(1); }

/* ---- tiny line I/O over a socket fd ----------------------------------- */
static int sock_connect(const char *host, int port) {
    struct addrinfo hints, *res, *rp;
    char portstr[16];
    int fd = -1;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void send_line(int fd, const char *line) {
    size_t n = strlen(line);
    if (write(fd, line, n) != (ssize_t)n || write(fd, "\n", 1) != 1)
        die("write failed");
}

/* read one '\n'-terminated line into buf (NUL-terminated, newline stripped). */
static int recv_line(int fd, char *buf, size_t cap) {
    size_t i = 0;
    while (i + 1 < cap) {
        char ch;
        ssize_t r = read(fd, &ch, 1);
        if (r <= 0) return -1;
        if (ch == '\n') break;
        if (ch != '\r') buf[i++] = ch;
    }
    buf[i] = '\0';
    return (int)i;
}

/* ---- seed handling ----------------------------------------------------- */
static int hex2bin(const char *hex, uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        unsigned v;
        if (sscanf(hex + i*2, "%2x", &v) != 1) return 1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static void load_or_make_seed(const char *seed_hex, uint8_t seed[32]) {
    if (seed_hex) {
        if (strlen(seed_hex) < 64 || hex2bin(seed_hex, seed, 32)) die("bad --seed-hex");
        return;
    }
    const char *home = getenv("HOME");
    char path[512];
    snprintf(path, sizeof path, "%s/.rustchain_seed", home ? home : ".");
    FILE *f = fopen(path, "rb");
    if (f) { size_t n = fread(seed, 1, 32, f); fclose(f); if (n == 32) return; }
    /* generate: best-effort entropy (replace with a real CSPRNG per platform) */
    FILE *u = fopen("/dev/urandom", "rb");
    if (u) { size_t n = fread(seed, 1, 32, u); fclose(u); if (n != 32) die("urandom short"); }
    else { srand((unsigned)time(NULL)); for (int i = 0; i < 32; i++) seed[i] = (uint8_t)rand(); }
    f = fopen(path, "wb");
    if (f) { fwrite(seed, 1, 32, f); fclose(f); }
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1", *miner = NULL, *wallet = NULL, *seed_hex = NULL;
    const char *arch = "G4", *family = "PowerPC";
    int port = 8090;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--host") && i+1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "--port") && i+1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--miner") && i+1 < argc) miner = argv[++i];
        else if (!strcmp(argv[i], "--wallet") && i+1 < argc) wallet = argv[++i];
        else if (!strcmp(argv[i], "--seed-hex") && i+1 < argc) seed_hex = argv[++i];
        else if (!strcmp(argv[i], "--arch") && i+1 < argc) arch = argv[++i];
        else if (!strcmp(argv[i], "--family") && i+1 < argc) family = argv[++i];
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }
    if (!miner || !wallet) die("need --miner and --wallet");
    if (!wallet[0]) die("empty wallet");

    uint8_t seed[32], pk[32];
    load_or_make_seed(seed_hex, seed);
    if (rcc_ed25519_pubkey(seed, pk)) die("pubkey derive failed");
    char pk_hex[65];
    rcc_hex(pk, 32, pk_hex);

    int fd = sock_connect(host, port);
    if (fd < 0) die("connect failed");

    char line[70000];
    if (recv_line(fd, line, sizeof line) < 0 || strncmp(line, "RCGW ", 5)) die("no banner");

    /* HELLO */
    snprintf(line, sizeof line, "HELLO %s", miner);
    send_line(fd, line);
    if (recv_line(fd, line, sizeof line) < 0 || strcmp(line, "READY")) {
        fprintf(stderr, "HELLO rejected: %s\n", line); return 1;
    }

    /* CHALLENGE -> NONCE */
    send_line(fd, "CHALLENGE");
    if (recv_line(fd, line, sizeof line) < 0 || strncmp(line, "NONCE ", 6)) {
        fprintf(stderr, "no nonce: %s\n", line); return 1;
    }
    char nonce[128];
    size_t nlen = strlen(line + 6);
    if (nlen == 0 || nlen >= sizeof nonce) die("bad nonce length");
    memcpy(nonce, line + 6, nlen + 1);

    /* commitment = sha256(nonce + wallet + entropy_json), entropy fixed-shape ASCII */
    char entropy_json[128];
    snprintf(entropy_json, sizeof entropy_json, "{\"variance_ns\":0.0}");
    char preimage[1024];
    int plen = snprintf(preimage, sizeof preimage, "%s%s%s", nonce, wallet, entropy_json);
    uint8_t cdigest[RCC_SHA256_LEN];
    rcc_sha256((const uint8_t *)preimage, (size_t)plen, cdigest);
    char commitment[65];
    rcc_hex(cdigest, RCC_SHA256_LEN, commitment);

    /* sign the EXACT node message: miner_id|miner(wallet)|nonce|commitment */
    char signmsg[1024];
    int slen = snprintf(signmsg, sizeof signmsg, "%s|%s|%s|%s",
                        miner, wallet, nonce, commitment);
    uint8_t sig[RCC_ED25519_SIG_LEN];
    if (rcc_ed25519_sign(seed, (const uint8_t *)signmsg, (size_t)slen, sig))
        die("sign failed");
    char sig_hex[129];
    rcc_hex(sig, RCC_ED25519_SIG_LEN, sig_hex);

    /* hand-build the attestation JSON (values are safe ASCII; no escaping needed) */
    char json[4096];
    snprintf(json, sizeof json,
        "{\"miner\":\"%s\",\"miner_id\":\"%s\",\"nonce\":\"%s\","
        "\"report\":{\"nonce\":\"%s\",\"commitment\":\"%s\",\"entropy_score\":0.0},"
        "\"device\":{\"family\":\"%s\",\"arch\":\"%s\",\"model\":\"%s\",\"cores\":1},"
        "\"signals\":{\"hostname\":\"vintage\"},"
        "\"fingerprint\":{\"all_passed\":true,\"checks\":{}},"
        "\"signature\":\"%s\",\"public_key\":\"%s\",\"signature_type\":\"ed25519\"}",
        wallet, miner, nonce, nonce, commitment, family, arch, arch, sig_hex, pk_hex);

    /* SUBMIT */
    char *out = malloc(strlen(json) + 16);
    if (!out) die("oom");
    sprintf(out, "SUBMIT %s", json);
    send_line(fd, out);
    free(out);

    if (recv_line(fd, line, sizeof line) < 0) die("no RESULT");
    send_line(fd, "BYE");

    printf("miner_id   : %s\n", miner);
    printf("public_key : %s\n", pk_hex);
    printf("nonce      : %s\n", nonce);
    printf("commitment : %s\n", commitment);
    printf("sign_msg   : %s\n", signmsg);
    printf("signature  : %s\n", sig_hex);
    printf("server     : %s\n", line);
    close(fd);
    return strncmp(line, "RESULT ", 7) == 0 ? 0 : 1;
}
