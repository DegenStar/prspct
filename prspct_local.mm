// PRSPCT local miner — Apple Silicon (Metal GPU) + CPU, keccak-256.
//
//   claimHash = keccak256(abi.encodePacked(bytes32 seed, address sender, uint256 nonce))
//             = 32 + 20 + 32 = 84 bytes, one keccak block (rate 136).
//
// Same wire protocol as prspct_cuda.cu, so prspct_miner.py drives either binary:
//   JOB <seed_hex64> <sender_hex40> <target_hex64>
//   TX  <txNonce> <maxFeeWei>          (updated every poll)
//   STOP
//   ->  RATE <hashes_per_sec>
//       FOUND <nonce_decimal> <hash_hex64>
//       SENT  <txhash> <nonce> <txNonce>
//       TXRES ok|err <ms> <url> [msg]
//
// Backends (env BACKEND=auto|metal|cpu|both, default auto):
//   metal  runtime-compiled MSL kernel — needs only the CLT SDK, not full Xcode
//   cpu    multithreaded C++ keccak over the same template
//   both   GPU and CPU at the same time
//
// Native tx-mode: with MINER_PRIVATE_KEY set the binary signs+broadcasts
// claim(nonce) itself (prspct_tx.h + bundled secp256k1, no libsecp256k1 needed).
// Without a key it reports FOUND and Python sends the transaction.
//
// Build (see Makefile):
//   clang++ -O3 -std=c++17 -fobjc-arc -framework Foundation -framework Metal \
//           -o prspct_local prspct_local.mm -lcurl

#include "prspct_tx.h"

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <sys/select.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace pr;

static std::mutex g_out;
static void out(const char *fmt, ...) {
  std::lock_guard<std::mutex> lk(g_out);
  va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
  fflush(stdout);
}

// ---------------- native tx-mode ----------------
static bool g_native = false;
static Wallet g_wallet;
static std::vector<std::string> g_rpcs;
static std::mutex g_txm;
static TxParams g_tx;
static bool g_tx_ready = false;
static uint64_t g_py_nonce = 0;
static uint64_t g_next_nonce = 0;

static void split_csv(const std::string &s, std::vector<std::string> &v) {
  size_t a = 0;
  while (a <= s.size()) {
    size_t b = s.find(',', a); if (b == std::string::npos) b = s.size();
    std::string t = s.substr(a, b - a);
    while (!t.empty() && isspace((unsigned char)t.front())) t.erase(t.begin());
    while (!t.empty() && isspace((unsigned char)t.back())) t.pop_back();
    if (!t.empty()) v.push_back(t);
    a = b + 1;
  }
}

static void init_native() {
  const char *k = getenv("MINER_PRIVATE_KEY");
  if (!k || !*k) { out("INFO txmode python (MINER_PRIVATE_KEY not set)\n"); return; }
  if (!g_wallet.init(k)) { out("INFO txmode python (bad key)\n"); return; }
  const char *r = getenv("RPC_URLS");
  split_csv(r ? r : "", g_rpcs);
  if (g_rpcs.empty()) split_csv(
    "https://rpc.mainnet.chain.robinhood.com,https://robinhood-rpc.publicnode.com,"
    "https://rpc.ordofi.network", g_rpcs);
  if (const char *tip = getenv("MIN_TIP_WEI")) {
    std::string t = tip;
    if (!t.empty() && t.find_first_not_of("0123456789") == std::string::npos) g_tx.tip_wei = t;
    else out("INFO MIN_TIP_WEI ignored (not a decimal number)\n");
  }
  curl_global_init(CURL_GLOBAL_DEFAULT);
  unhex("0xd078008c3D887A52CE722A3cA0539cA1F4971dD1", g_tx.to);
  g_native = true;
  out("INFO txmode native address %s rpcs=%zu\n", hex(g_wallet.address).c_str(), g_rpcs.size());
}

static bool send_once(const TxParams &p, uint64_t nonce, bool &nonce_err) {
  bytes raw, h;
  if (!build_claim_tx(g_wallet, p, nonce, raw, h)) { out("ERR sign failed\n"); return false; }
  std::string raw_hex = hex(raw);
  out("SENT %s %llu %llu\n", hex(h).c_str(), (unsigned long long)nonce, (unsigned long long)p.tx_nonce);
  auto ok = std::make_shared<std::atomic<int>>(0), err = std::make_shared<std::atomic<int>>(0), nerr = std::make_shared<std::atomic<int>>(0);
  auto done = std::make_shared<std::atomic<int>>(0);
  size_t n = g_rpcs.size();
  broadcast(g_rpcs, raw_hex, [=](const SendResult &r) {
    std::string u = r.url; size_t s = u.find("//"); if (s != std::string::npos) u = u.substr(s + 2); if (u.size() > 28) u.resize(28);
    if (r.ok) { (*ok)++; out("TXRES ok %.0f %s %s\n", r.ms, u.c_str(), r.msg.c_str()); }
    else {
      std::string low = r.msg; for (auto &c : low) c = (char)tolower(c);
      if (low.find("nonce") != std::string::npos) (*nerr)++;
      (*err)++; out("TXRES err %.0f %s %s\n", r.ms, u.c_str(), r.msg.c_str());
    }
    (*done)++;
  });
  auto t0 = std::chrono::steady_clock::now();
  while (*ok == 0 && (size_t)*done < n && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(9))
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  nonce_err = (*ok == 0 && *nerr > 0 && (size_t)(*nerr) >= (size_t)*done / 2 + 1);
  return *ok > 0;
}

static void native_submit(uint64_t nonce) {
  TxParams p; uint64_t pyn;
  {
    std::lock_guard<std::mutex> lk(g_txm);
    if (!g_tx_ready) { out("ERR tx params not set yet — FOUND not sent\n"); return; }
    p = g_tx; pyn = g_py_nonce;
    if (g_next_nonce < pyn) g_next_nonce = pyn;
    p.tx_nonce = g_next_nonce;
    g_next_nonce++;
  }
  bool nonce_err = false;
  if (send_once(p, nonce, nonce_err)) return;
  if (nonce_err && p.tx_nonce != pyn) {
    out("INFO nonce resync %llu -> %llu\n", (unsigned long long)p.tx_nonce, (unsigned long long)pyn);
    { std::lock_guard<std::mutex> lk(g_txm); g_next_nonce = pyn + 1; }
    p.tx_nonce = pyn;
    bool dummy; send_once(p, nonce, dummy);
  }
}

// ---------------- keccak-256 ----------------
static const uint64_t KRC24[24] = {
  0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
  0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
  0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL };

static inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

// keccak-f[1600] over the 17 message lanes; lane 9 / lane 10 carry the nonce.
#ifndef PR_KECCAK_UNROLL
#define PR_KECCAK_UNROLL full
#endif
static inline void keccakf_local(uint64_t s[25]) {
  uint64_t t, bc[5];
#pragma clang loop unroll(PR_KECCAK_UNROLL)
  for (int r = 0; r < 24; r++) {
    for (int i = 0; i < 5; i++) bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
    for (int i = 0; i < 5; i++) {
      t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (int j = 0; j < 25; j += 5) s[j + i] ^= t;
    }
    t = s[1];
    s[1] = rotl64(s[6], 44);  s[6] = rotl64(s[9], 20);  s[9] = rotl64(s[22], 61); s[22] = rotl64(s[14], 39);
    s[14] = rotl64(s[20], 18); s[20] = rotl64(s[2], 62); s[2] = rotl64(s[12], 43); s[12] = rotl64(s[13], 25);
    s[13] = rotl64(s[19], 8);  s[19] = rotl64(s[23], 56); s[23] = rotl64(s[15], 41); s[15] = rotl64(s[4], 27);
    s[4] = rotl64(s[24], 14);  s[24] = rotl64(s[21], 2);  s[21] = rotl64(s[8], 55); s[8] = rotl64(s[16], 45);
    s[16] = rotl64(s[5], 36);  s[5] = rotl64(s[3], 28);   s[3] = rotl64(s[18], 21); s[18] = rotl64(s[17], 15);
    s[17] = rotl64(s[11], 10); s[11] = rotl64(s[7], 6);   s[7] = rotl64(s[10], 3);  s[10] = rotl64(t, 1);
    for (int j = 0; j < 25; j += 5) {
      for (int i = 0; i < 5; i++) bc[i] = s[j + i];
      for (int i = 0; i < 5; i++) s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }
    s[0] ^= KRC24[r];
  }
}

// ---------------- job ----------------
struct Job {
  uint64_t tpl[17] = {0};     // message lanes, nonce bytes zeroed
  uint64_t target[4] = {0};   // target as 4 big-endian 64-bit words
  uint8_t seed[32] = {0};
  uint8_t sender[20] = {0};
  bool valid = false;
};

static std::mutex g_job_m;
static Job g_job;
static std::atomic<uint64_t> g_gen{0};
static std::atomic<uint64_t> g_hashes{0};
static std::atomic<bool> g_stop{false};
static std::mt19937_64 g_rng(std::chrono::steady_clock::now().time_since_epoch().count() ^ getpid());

static inline uint64_t bswap64(uint64_t x) { return __builtin_bswap64(x); }

// nonce bytes (big-endian uint256) land in lane 9 (bytes 76..79) and lane 10 (80..83)
static inline void splice_nonce(uint64_t s[25], uint64_t nonce) {
  uint64_t be = bswap64(nonce);
  s[9]  |= (be & 0xFFFFFFFFULL) << 32;
  s[10] |= (be >> 32) & 0xFFFFFFFFULL;
}

static inline void template_lanes(const Job &j, uint64_t s[25]) {
  for (int i = 0; i < 17; i++) s[i] = j.tpl[i];
  for (int i = 17; i < 25; i++) s[i] = 0;
}

// hash words as 4 big-endian 64-bit words -> plain lexicographic compare
static inline void hash_words(const uint64_t s[25], uint64_t h[4]) {
  for (int i = 0; i < 4; i++) h[i] = bswap64(s[i]);
}
static inline bool below_target(const uint64_t h[4], const uint64_t t[4]) {
  for (int i = 0; i < 4; i++) { if (h[i] < t[i]) return true; if (h[i] > t[i]) return false; }
  return false;   // equal is not below
}

static bool hex_to_bytes(const std::string &in, uint8_t *out, size_t n) {
  std::string s = in; if (s.rfind("0x", 0) == 0) s = s.substr(2);
  if (s.size() != n * 2) return false;
  for (size_t i = 0; i < n; i++) {
    int hi = hv(s[2 * i]), lo = hv(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)(hi * 16 + lo);
  }
  return true;
}

// seed(32) | sender(20) | nonce(32, zeroed) | pad10*1 -> 17 little-endian lanes
static bool build_job(Job &j, const std::string &seed_hex, const std::string &sender_hex,
                      const std::string &target_hex) {
  uint8_t buf[136]; memset(buf, 0, sizeof buf);
  if (!hex_to_bytes(seed_hex, j.seed, 32)) return false;
  if (!hex_to_bytes(sender_hex, j.sender, 20)) return false;
  memcpy(buf, j.seed, 32);
  memcpy(buf + 32, j.sender, 20);
  buf[84] = 0x01;    // message is 84 bytes long
  buf[135] = 0x80;   // rate boundary marker
  for (int i = 0; i < 17; i++) {
    uint64_t v = 0;
    for (int b = 0; b < 8; b++) v |= (uint64_t)buf[i * 8 + b] << (8 * b);
    j.tpl[i] = v;
  }
  uint8_t tb[32];
  if (!hex_to_bytes(target_hex, tb, 32)) return false;
  for (int i = 0; i < 4; i++) {
    uint64_t v = 0;
    for (int b = 0; b < 8; b++) v = (v << 8) | tb[i * 8 + b];
    j.target[i] = v;
  }
  j.valid = true;
  return true;
}

// single nonce -> hash (used for host-side verification of every reported hit)
static bool hash_nonce(const Job &j, uint64_t nonce, uint64_t h[4]) {
  uint64_t s[25];
  template_lanes(j, s);
  splice_nonce(s, nonce);
  keccakf_local(s);
  hash_words(s, h);
  return below_target(h, j.target);
}

// ---------------- hit queue ----------------
struct Hit { uint64_t nonce; uint64_t hash[4]; uint64_t gen; const char *src; };
static std::mutex g_hits_m;
static std::vector<Hit> g_hits;

// Cap concurrent claim submissions: a pathological (easy) target can report
// thousands of hits per second and an unbounded thread-per-hit fan-out would
// starve the process long before any of them could be mined.
static std::atomic<int> g_inflight{0};
static std::atomic<long long> g_last_backlog_log{0};
static const int kMaxInflight = 4;

static void submit_hit_async(uint64_t nonce) {
  if (g_inflight.load(std::memory_order_relaxed) >= kMaxInflight) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::steady_clock::now().time_since_epoch()).count();
    if (now != g_last_backlog_log.exchange(now)) out("INFO submit backlog — dropping extra hits\n");
    return;
  }
  g_inflight.fetch_add(1, std::memory_order_relaxed);
  std::thread([nonce]() {
    native_submit(nonce);
    g_inflight.fetch_sub(1, std::memory_order_relaxed);
  }).detach();
}

static void push_hit(uint64_t nonce, const uint64_t h[4], uint64_t gen, const char *src) {
  std::lock_guard<std::mutex> lk(g_hits_m);
  if (g_hits.size() < 64) g_hits.push_back(Hit{nonce, {h[0], h[1], h[2], h[3]}, gen, src});
}

// ---------------- CPU backend ----------------
static int g_cpu_threads = 0;
static std::vector<std::thread> g_cpu_workers;

static void cpu_worker(int id, uint64_t start) {
  (void)id;
  uint64_t nonce = start;
  const uint64_t STRIDE = 1ULL << 41;      // keep worker ranges far apart
  while (!g_stop.load(std::memory_order_relaxed)) {
    uint64_t gen = g_gen.load(std::memory_order_acquire);
    Job job;
    { std::lock_guard<std::mutex> lk(g_job_m); job = g_job; }
    if (!job.valid) { std::this_thread::sleep_for(std::chrono::milliseconds(2)); continue; }

    uint64_t h[4];
    for (int k = 0; k < 8192; k++) {
      uint64_t s[25];
      template_lanes(job, s);
      splice_nonce(s, nonce);
      keccakf_local(s);
      hash_words(s, h);
      if (below_target(h, job.target)) push_hit(nonce, h, gen, "cpu");
      nonce++;
      if (nonce >= start + STRIDE) nonce = start;   // wrap inside our own range
    }
    g_hashes.fetch_add(8192, std::memory_order_relaxed);
    if (g_gen.load(std::memory_order_acquire) != gen) nonce = start + (g_rng() % STRIDE);
  }
}

static void start_cpu(int threads) {
  g_cpu_threads = threads;
  for (int i = 0; i < threads; i++) {
    uint64_t start = g_rng() % (1ULL << 48);
    g_cpu_workers.emplace_back(cpu_worker, i, start);
  }
}

// ---------------- Metal backend ----------------
static const char *kMslSource = R"MSL(
#include <metal_stdlib>
using namespace metal;

#ifndef PER_NONCES
#define PER_NONCES 1
#endif

struct Params {
  ulong tpl[17];
  ulong target[4];
  ulong base;
};

constant ulong RC[24] = {
  0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
  0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
  0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
  0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
  0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
  0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL };

inline ulong rotl64(ulong x, uint n) { return (x << n) | (x >> (64 - n)); }
inline ulong bswap64(ulong x) {
  return ((x & 0x00000000000000FFUL) << 56) | ((x & 0x000000000000FF00UL) << 40) |
         ((x & 0x0000000000FF0000UL) << 24) | ((x & 0x00000000FF000000UL) << 8)  |
         ((x & 0x000000FF00000000UL) >> 8)  | ((x & 0x0000FF0000000000UL) >> 24) |
         ((x & 0x00FF000000000000UL) >> 40) | ((x & 0xFF00000000000000UL) >> 56);
}

inline void keccakf(thread ulong s[25]) {
  ulong t, bc[5];
  for (int r = 0; r < 24; r++) {
#pragma clang loop unroll(full)
    for (int i = 0; i < 5; i++) bc[i] = s[i] ^ s[i+5] ^ s[i+10] ^ s[i+15] ^ s[i+20];
#pragma clang loop unroll(full)
    for (int i = 0; i < 5; i++) {
      t = bc[(i+4)%5] ^ rotl64(bc[(i+1)%5], 1);
      for (int j = 0; j < 25; j += 5) s[j+i] ^= t;
    }
    t = s[1];
    s[1] = rotl64(s[6], 44);  s[6] = rotl64(s[9], 20);  s[9] = rotl64(s[22], 61); s[22] = rotl64(s[14], 39);
    s[14] = rotl64(s[20], 18); s[20] = rotl64(s[2], 62); s[2] = rotl64(s[12], 43); s[12] = rotl64(s[13], 25);
    s[13] = rotl64(s[19], 8);  s[19] = rotl64(s[23], 56); s[23] = rotl64(s[15], 41); s[15] = rotl64(s[4], 27);
    s[4] = rotl64(s[24], 14);  s[24] = rotl64(s[21], 2);  s[21] = rotl64(s[8], 55); s[8] = rotl64(s[16], 45);
    s[16] = rotl64(s[5], 36);  s[5] = rotl64(s[3], 28);   s[3] = rotl64(s[18], 21); s[18] = rotl64(s[17], 15);
    s[17] = rotl64(s[11], 10); s[11] = rotl64(s[7], 6);   s[7] = rotl64(s[10], 3);  s[10] = rotl64(t, 1);
#pragma clang loop unroll(full)
    for (int j = 0; j < 25; j += 5) {
      for (int i = 0; i < 5; i++) bc[i] = s[j+i];
      for (int i = 0; i < 5; i++) s[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
    }
    s[0] ^= RC[r];
  }
}

kernel void mine(device const Params *P [[buffer(0)]],
                 device ulong *out_nonce [[buffer(1)]],
                 device ulong *out_hash [[buffer(2)]],
                 device atomic_uint *out_cnt [[buffer(3)]],
                 uint gid [[thread_position_in_grid]]) {
  ulong tpl[17];
  for (int i = 0; i < 17; i++) tpl[i] = P->tpl[i];
  ulong nonce0 = P->base + (ulong)gid * PER_NONCES;

  for (uint k = 0; k < PER_NONCES; k++) {
    ulong nonce = nonce0 + k;
    ulong s[25];
    for (int i = 0; i < 17; i++) s[i] = tpl[i];
    for (int i = 17; i < 25; i++) s[i] = 0;
    ulong be = bswap64(nonce);
    s[9]  |= (be & 0xFFFFFFFFUL) << 32;
    s[10] |= (be >> 32) & 0xFFFFFFFFUL;
    keccakf(s);

    ulong h0 = bswap64(s[0]);
    if (h0 > P->target[0]) continue;
    ulong h1 = bswap64(s[1]);
    if (h0 == P->target[0]) {
      if (h1 > P->target[1]) continue;
      if (h1 == P->target[1]) {
        ulong h2 = bswap64(s[2]);
        if (h2 > P->target[2]) continue;
        if (h2 == P->target[2] && bswap64(s[3]) >= P->target[3]) continue;
      }
    }
    uint idx = atomic_fetch_add_explicit(out_cnt, 1u, memory_order_relaxed);
    if (idx < 8u) {
      out_nonce[idx] = nonce;
      out_hash[idx*4+0] = h0;
      out_hash[idx*4+1] = h1;
      out_hash[idx*4+2] = bswap64(s[2]);
      out_hash[idx*4+3] = bswap64(s[3]);
    }
  }
}
)MSL";

struct GpuParams {
  uint64_t tpl[17];
  uint64_t target[4];
  uint64_t base;
};

struct MetalBackend {
  id<MTLDevice> dev = nil;
  id<MTLCommandQueue> queue = nil;
  id<MTLComputePipelineState> pipe = nil;
  id<MTLBuffer> params = nil, hit_nonce = nil, hit_hash = nil, counter = nil;
  uint64_t batch = 1ULL << 22;
  uint32_t tg = 64;
  uint32_t per = 1;
  uint64_t base = 0;
  std::thread th;

  bool init(std::string &err) {
    @autoreleasepool {
      dev = MTLCreateSystemDefaultDevice();
      if (!dev) {
        NSArray<id<MTLDevice>> *all = MTLCopyAllDevices();
        if ([all count]) dev = all[0];
      }
      if (!dev) { err = "no Metal device"; return false; }
      NSError *e = nil;
      MTLCompileOptions *opt = [MTLCompileOptions new];
      opt.mathMode = MTLMathModeFast;
      if (const char *b = getenv("METAL_BATCH")) {
        uint64_t v = strtoull(b, nullptr, 10);
        if (v >= 65536 && v <= (1ULL << 32)) batch = v;
      }
      if (const char *t = getenv("METAL_TG")) {
        uint32_t v = (uint32_t)strtoul(t, nullptr, 10);
        if (v >= 1 && v <= 1024) tg = v;
      }
      if (const char *t = getenv("METAL_PER")) {
        uint32_t v = (uint32_t)strtoul(t, nullptr, 10);
        if (v >= 1 && v <= 64) per = v;
      }
      std::string src = "#define PER_NONCES " + std::to_string(per) + "\n" + kMslSource;
      id<MTLLibrary> lib = [dev newLibraryWithSource:[NSString stringWithUTF8String:src.c_str()]
                                             options:opt error:&e];
      if (!lib) { err = std::string("MSL compile failed: ") + [[e localizedDescription] UTF8String]; return false; }
      id<MTLFunction> fn = [lib newFunctionWithName:@"mine"];
      if (!fn) { err = "kernel 'mine' missing"; return false; }
      pipe = [dev newComputePipelineStateWithFunction:fn error:&e];
      if (!pipe) { err = std::string("pipeline failed: ") + [[e localizedDescription] UTF8String]; return false; }
      queue = [dev newCommandQueue];
      params = [dev newBufferWithLength:sizeof(GpuParams) options:MTLResourceStorageModeShared];
      hit_nonce = [dev newBufferWithLength:8 * sizeof(uint64_t) options:MTLResourceStorageModeShared];
      hit_hash = [dev newBufferWithLength:32 * sizeof(uint64_t) options:MTLResourceStorageModeShared];
      counter = [dev newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];
      if (!queue || !params || !hit_nonce || !hit_hash || !counter) { err = "buffer alloc failed"; return false; }
      err = std::string("device=") + [[dev name] UTF8String];
      return true;
    }
  }

  void run() {
    while (!g_stop.load(std::memory_order_relaxed)) {
      uint64_t gen = g_gen.load(std::memory_order_acquire);
      Job job;
      { std::lock_guard<std::mutex> lk(g_job_m); job = g_job; }
      if (!job.valid) { std::this_thread::sleep_for(std::chrono::milliseconds(2)); continue; }

      @autoreleasepool {
        GpuParams *pp = (GpuParams *)[params contents];
        memcpy(pp->tpl, job.tpl, sizeof pp->tpl);
        memcpy(pp->target, job.target, sizeof pp->target);
        pp->base = base;
        *(uint32_t *)[counter contents] = 0;

        id<MTLCommandBuffer> cb = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
        [enc setComputePipelineState:pipe];
        [enc setBuffer:params offset:0 atIndex:0];
        [enc setBuffer:hit_nonce offset:0 atIndex:1];
        [enc setBuffer:hit_hash offset:0 atIndex:2];
        [enc setBuffer:counter offset:0 atIndex:3];
        [enc dispatchThreads:MTLSizeMake(batch, 1, 1) threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
        [enc endEncoding];
        [cb commit];
        [cb waitUntilCompleted];
        if (cb.error) {
          out("ERR metal command buffer failed: %s\n", [[cb.error localizedDescription] UTF8String]);
          std::this_thread::sleep_for(std::chrono::milliseconds(500));
          continue;
        }
      }

      uint32_t found = *(uint32_t *)[counter contents];
      if (g_gen.load(std::memory_order_acquire) != gen) {   // stale job -> throw the batch away
        base = g_rng();
        continue;
      }
      if (found) {
        uint64_t *nn = (uint64_t *)[hit_nonce contents];
        uint64_t *hh = (uint64_t *)[hit_hash contents];
        for (uint32_t i = 0; i < found && i < 8; i++) push_hit(nn[i], hh + 4 * i, gen, "gpu");
      }
      g_hashes.fetch_add(batch * per, std::memory_order_relaxed);
      base += batch * per;
    }
  }
};

// ---------------- stdin handling ----------------
// Read with read(2) instead of fgets(3): stdio happily buffers a second line
// that select(2) will never report as pending, which loses commands sent in the
// same batch as the line we just consumed.
static std::string g_inbuf;
static bool g_stdin_eof = false;

static void pump_stdin(std::vector<std::string> &lines) {
  for (;;) {
    fd_set fds; FD_ZERO(&fds); FD_SET(0, &fds);
    struct timeval tv = {0, 0};
    if (select(1, &fds, nullptr, nullptr, &tv) <= 0) break;
    char buf[4096];
    ssize_t n = read(0, buf, sizeof buf);
    if (n == 0) { g_stdin_eof = true; break; }
    if (n < 0) break;
    g_inbuf.append(buf, (size_t)n);
  }
  size_t pos;
  while ((pos = g_inbuf.find('\n')) != std::string::npos) {
    std::string l = g_inbuf.substr(0, pos);
    g_inbuf.erase(0, pos + 1);
    while (!l.empty() && (l.back() == '\r' || l.back() == '\n')) l.pop_back();
    if (!l.empty()) lines.push_back(l);
  }
}

int main() {
  setvbuf(stdout, nullptr, _IOLBF, 0);

  std::string backend = getenv("BACKEND") ? getenv("BACKEND") : "auto";
  int want_cpu = 0;
  if (const char *t = getenv("CPU_THREADS")) want_cpu = atoi(t);
  else want_cpu = (int)std::thread::hardware_concurrency();
  if (want_cpu <= 0) want_cpu = 4;

  init_native();

  MetalBackend metal;
  bool metal_ok = false;
  if (backend != "cpu") {
    std::string info;
    metal_ok = metal.init(info);
    if (metal_ok) {
      metal.base = g_rng();
      out("INFO metal ready %s batch=%llu tg=%u per=%u\n", info.c_str(),
          (unsigned long long)metal.batch, metal.tg, metal.per);
    } else {
      out("INFO metal unavailable (%s)%s\n", info.c_str(),
          backend == "metal" ? " — falling back to cpu" : "");
    }
  }
  if (backend == "metal" && !metal_ok) { out("ERR no usable backend\n"); return 1; }

  // "auto"/"both" run everything we have: Metal GPU plus the CPU cores.
  bool use_cpu = (backend != "metal") || !metal_ok;
  if (use_cpu) {
    start_cpu(want_cpu);
    for (auto &t : g_cpu_workers) t.detach();
    out("INFO cpu threads=%d\n", want_cpu);
  }
  if (metal_ok) {
    metal.th = std::thread([&metal]() { metal.run(); });
    metal.th.detach();
  }
  out("INFO backend %s%s\n", metal_ok ? "metal" : "", (use_cpu && metal_ok) ? "+cpu" : (use_cpu ? "cpu" : ""));

  uint64_t last_hashes = 0;
  auto last_rate = std::chrono::steady_clock::now();
  std::string line;

  while (true) {
    std::vector<std::string> inlines;
    pump_stdin(inlines);
    if (g_stdin_eof) { out("INFO stdin closed, exiting\n"); g_stop = true; return 0; }
    for (const std::string &line : inlines) {
      char cmd[16], a[128], b[128], c[128], d[128];
      int nf = sscanf(line.c_str(), "%15s %127s %127s %127s %127s", cmd, a, b, c, d);
      if (nf >= 4 && strcmp(cmd, "JOB") == 0) {
        Job j;
        if (build_job(j, a, b, c)) {
          { std::lock_guard<std::mutex> lk(g_job_m); g_job = j; }
          uint64_t nb = g_rng();
          metal.base = nb;
          g_gen.fetch_add(1, std::memory_order_release);
          out("INFO job accepted\n");
        } else out("ERR bad job\n");
      } else if (nf == 3 && strcmp(cmd, "TX") == 0) {
        std::lock_guard<std::mutex> lk(g_txm);
        g_py_nonce = strtoull(a, nullptr, 10);
        g_tx.max_fee_wei = b;
        if (!g_tx_ready) { g_next_nonce = g_py_nonce; g_tx_ready = true; out("INFO tx params ready nonce=%llu\n", (unsigned long long)g_py_nonce); }
      } else if (strcmp(line.c_str(), "STOP") == 0) {
        std::lock_guard<std::mutex> lk(g_job_m);
        g_job.valid = false;
        g_gen.fetch_add(1, std::memory_order_release);
        out("INFO stopped\n");
      } else out("ERR unknown line\n");
    }
    bool got_line = !inlines.empty();

    // report hits (host-verified before we claim anything)
    {
      std::vector<Hit> hits;
      { std::lock_guard<std::mutex> lk(g_hits_m); hits.swap(g_hits); }
      for (auto &h : hits) {
        Job job;
        { std::lock_guard<std::mutex> lk(g_job_m); job = g_job; }
        // Hits mined before a job switch are worthless (the hash binds the seed),
        // so drop them quietly instead of crying wolf.
        if (!job.valid || h.gen != g_gen.load(std::memory_order_acquire)) continue;
        uint64_t check[4];
        bool ok = hash_nonce(job, h.nonce, check);
        if (!ok) { out("ERR %s hit rejected by host keccak (nonce %llu)\n", h.src, (unsigned long long)h.nonce); continue; }
        if (memcmp(check, h.hash, sizeof check) != 0) {
          out("ERR %s hit hash mismatch (nonce %llu)\n", h.src, (unsigned long long)h.nonce);
          continue;
        }
        if (g_native) {
          submit_hit_async(h.nonce);
        }
        out("FOUND %llu %016llx%016llx%016llx%016llx\n", (unsigned long long)h.nonce,
            (unsigned long long)check[0], (unsigned long long)check[1],
            (unsigned long long)check[2], (unsigned long long)check[3]);
      }
    }

    auto now = std::chrono::steady_clock::now();
    double dt = std::chrono::duration<double>(now - last_rate).count();
    if (dt >= 2.0) {
      uint64_t total = g_hashes.load(std::memory_order_relaxed);
      out("RATE %.0f\n", (double)(total - last_hashes) / dt);
      last_hashes = total;
      last_rate = now;
    }

    if (!got_line) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}
