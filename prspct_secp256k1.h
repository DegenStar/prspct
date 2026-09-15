// prspct_secp256k1.h — self-contained secp256k1 ECDSA signer (RFC 6979, low-S, recovery id).
//
// Why this exists: the CUDA build links against libsecp256k1, which is packaged on
// Linux (`libsecp256k1-dev`). macOS ships no such library and Apple Silicon has no
// NVIDIA GPU, so the local build has to bring its own signer. This header is a
// drop-in replacement for the tiny slice of libsecp256k1 that prspct_tx.h uses:
//
//   ctx   = secp256k1_context_create(...)        -> Wallet::init()
//   pubkey_create / serialize                    -> Wallet::init()
//   ecdsa_sign_recoverable + serialize_compact   -> Wallet::sign()
//
// Everything is plain C++17: 256-bit field (mod p) and scalar (mod n) arithmetic on
// 4x64-bit limbs, Jacobian point arithmetic, HMAC-SHA256. No external dependencies.
//
// Correctness notes:
//   * inputs are reduced mod p / mod n before every operation, results are canonical
//   * k comes from RFC 6979 (deterministic, no RNG to get wrong)
//   * S is normalized to low-S and the recovery id is flipped accordingly
//   * scalar multiplication is not constant time — this signs a local burner
//     wallet, no remote party can observe the timing
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace pr {
namespace ec {

typedef uint64_t u64;
typedef unsigned __int128 u128;
typedef std::vector<uint8_t> bytes;

// ---------------- 256-bit integers (little-endian 64-bit limbs) ----------------
struct U256 { u64 w[4]; };

// secp256k1 domain parameters
static const U256 F_P = {{0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
                          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}};
static const U256 F_N = {{0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
                          0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL}};
static const U256 F_GX = {{0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
                           0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL}};
static const U256 F_GY = {{0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
                           0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL}};

static inline int cmp(const U256 &a, const U256 &b) {
  for (int i = 3; i >= 0; i--) { if (a.w[i] != b.w[i]) return a.w[i] < b.w[i] ? -1 : 1; }
  return 0;
}
static inline bool is_zero(const U256 &a) { return (a.w[0] | a.w[1] | a.w[2] | a.w[3]) == 0; }

// a - b, returns the borrow (1 if a < b)
static inline u64 sub4(u64 *r, const u64 *a, const u64 *b) {
  u64 carry = 0;
  for (int i = 0; i < 4; i++) {
    u128 t = (u128)a[i] - b[i] - carry;
    r[i] = (u64)t; carry = (u64)((t >> 64) & 1);
  }
  return carry;
}
static inline u64 add4(u64 *r, const u64 *a, const u64 *b) {
  u64 carry = 0;
  for (int i = 0; i < 4; i++) {
    u128 t = (u128)a[i] + b[i] + carry;
    r[i] = (u64)t; carry = (u64)(t >> 64);
  }
  return carry;
}

static inline bool ge(const U256 &a, const U256 &b) { return cmp(a, b) >= 0; }

// ---------------- field arithmetic (mod p) ----------------
// p = 2^256 - c, c = 2^32 + 977, so 2^256 = c (mod p): fold the high half instead
// of doing a full division.
static const u64 FOLD_C = 0x1000003D1ULL;   // 2^32 + 977

static inline void fe_add(U256 &r, const U256 &a, const U256 &b) {
  u64 carry = add4(r.w, a.w, b.w);
  if (carry || ge(r, F_P)) sub4(r.w, r.w, F_P.w);
}
static inline void fe_sub(U256 &r, const U256 &a, const U256 &b) {
  u64 borrow = sub4(r.w, a.w, b.w);
  if (borrow) add4(r.w, r.w, F_P.w);
}
static inline void fe_double(U256 &r, const U256 &a) { fe_add(r, a, a); }

static inline void fe_mul(U256 &out, const U256 &a, const U256 &b) {
  u64 t[8] = {0};
  for (int i = 0; i < 4; i++) {
    u64 carry = 0;
    for (int j = 0; j < 4; j++) {
      u128 cur = (u128)a.w[i] * b.w[j] + t[i + j] + carry;
      t[i + j] = (u64)cur;
      carry = (u64)(cur >> 64);
    }
    t[i + 4] = carry;
  }

  // fold: value = L + H * 2^256 = L + H * c
  u64 hc[5] = {0, 0, 0, 0, 0};
  u128 carry = 0;
  for (int j = 0; j < 4; j++) {
    u128 cur = (u128)t[4 + j] * FOLD_C + carry;
    hc[j] = (u64)cur; carry = cur >> 64;
  }
  hc[4] = (u64)carry;

  u64 r[5]; u128 s = 0;
  for (int j = 0; j < 5; j++) {
    u128 cur = (u128)hc[j] + (j < 4 ? t[j] : 0) + (u64)s;
    r[j] = (u64)cur; s = cur >> 64;
  }

  // fold the (small) overflow limb until nothing is left above 2^256
  while (r[4]) {
    u128 cur = (u128)r[4] * FOLD_C;
    u64 add[2] = {(u64)cur, (u64)(cur >> 64)};
    r[4] = 0;
    u64 c2 = 0;
    for (int j = 0; j < 4; j++) {
      u128 t2 = (u128)r[j] + (j < 2 ? add[j] : 0) + c2;
      r[j] = (u64)t2; c2 = (u64)(t2 >> 64);
    }
    r[4] = c2;
  }
  U256 v; memcpy(v.w, r, sizeof v.w);
  if (ge(v, F_P)) sub4(v.w, v.w, F_P.w);
  out = v;
}

static inline void fe_sqr(U256 &r, const U256 &a) { fe_mul(r, a, a); }

// a^(p-2) mod p = a^-1
static void fe_inv(U256 &out, const U256 &a) {
  const u64 two[4] = {2, 0, 0, 0};
  U256 e = F_P;
  sub4(e.w, e.w, two);   // p - 2
  U256 r = {{1, 0, 0, 0}}, b = a;
  for (int i = 0; i < 256; i++) {
    if ((e.w[i >> 6] >> (i & 63)) & 1) fe_mul(r, r, b);
    fe_sqr(b, b);
  }
  out = r;
}

// ---------------- scalar arithmetic (mod n) ----------------
static inline void sc_add(U256 &r, const U256 &a, const U256 &b) {
  u64 carry = add4(r.w, a.w, b.w);
  if (carry || ge(r, F_N)) sub4(r.w, r.w, F_N.w);
}
static inline void sc_sub(U256 &r, const U256 &a, const U256 &b) {
  u64 borrow = sub4(r.w, a.w, b.w);
  if (borrow) add4(r.w, r.w, F_N.w);
}
static inline bool sc_is_high(const U256 &a) {   // a > n/2 ?
  const u64 one[4] = {1, 0, 0, 0};
  U256 half; sub4(half.w, F_N.w, one);
  for (int i = 0; i < 4; i++) half.w[i] = (half.w[i] >> 1) | (i < 3 ? (half.w[i + 1] << 63) : 0);
  return cmp(a, half) > 0;
}

// reduce a 512-bit value mod n (schoolbook binary division; signing is rare)
static void sc_reduce(const u64 x[8], U256 &out) {
  u64 rem[5] = {0, 0, 0, 0, 0};
  for (int i = 511; i >= 0; i--) {
    u64 bit = (x[i >> 6] >> (i & 63)) & 1;
    u64 carry = bit;
    for (int j = 0; j < 5; j++) { u64 nc = rem[j] >> 63; rem[j] = (rem[j] << 1) | carry; carry = nc; }
    // rem < 2n here, so one conditional subtraction is enough
    bool gt = rem[4] != 0;
    if (!gt) {
      for (int j = 3; j >= 0; j--) {
        if (rem[j] != F_N.w[j]) { gt = rem[j] > F_N.w[j]; break; }
      }
    }
    if (gt) {
      u64 borrow = 0;
      for (int j = 0; j < 4; j++) {
        u128 t = (u128)rem[j] - F_N.w[j] - borrow;
        rem[j] = (u64)t; borrow = (u64)((t >> 64) & 1);
      }
      rem[4] -= borrow;
    }
  }
  memcpy(out.w, rem, sizeof out.w);
}

static inline void sc_mul(U256 &r, const U256 &a, const U256 &b) {
  u64 t[8] = {0};
  for (int i = 0; i < 4; i++) {
    u64 carry = 0;
    for (int j = 0; j < 4; j++) {
      u128 cur = (u128)a.w[i] * b.w[j] + t[i + j] + carry;
      t[i + j] = (u64)cur; carry = (u64)(cur >> 64);
    }
    t[i + 4] = carry;
  }
  sc_reduce(t, r);
}

// a^(n-2) mod n = a^-1 (n is prime)
static void sc_inv(U256 &out, const U256 &a) {
  const u64 two[4] = {2, 0, 0, 0};
  U256 e = F_N;
  sub4(e.w, e.w, two);
  U256 r = {{1, 0, 0, 0}}, b = a;
  for (int i = 0; i < 256; i++) {
    if ((e.w[i >> 6] >> (i & 63)) & 1) sc_mul(r, r, b);
    sc_mul(b, b, b);
  }
  out = r;
}

// ---------------- point arithmetic (Jacobian) ----------------
struct Jac { U256 x, y, z; };
static inline bool jac_inf(const Jac &p) { return is_zero(p.z); }

static Jac jac_double(const Jac &p) {
  if (jac_inf(p) || is_zero(p.y)) return Jac{{0,0,0,0}, {0,0,0,0}, {0,0,0,0}};
  U256 A, B, C, D, E, F, t, t2;
  fe_sqr(A, p.x);                      // A = X^2
  fe_sqr(B, p.y);                      // B = Y^2
  fe_sqr(C, B);                        // C = B^2
  fe_add(t, p.x, B); fe_sqr(t, t);     // (X+B)^2
  fe_sub(t, t, A); fe_sub(t, t, C);    // - A - C
  fe_double(D, t);                     // D = 2*((X+B)^2 - A - C)
  fe_double(E, A); fe_add(E, E, A);    // E = 3A
  fe_sqr(F, E);                        // F = E^2
  Jac o;
  fe_double(t, D);
  fe_sub(o.x, F, t);                   // X3 = F - 2D
  fe_sub(t, D, o.x);
  fe_mul(t, E, t);                     // E*(D - X3)
  U256 eightC; fe_double(eightC, C); fe_double(eightC, eightC); fe_double(eightC, eightC);
  fe_sub(o.y, t, eightC);              // Y3 = E*(D-X3) - 8C
  fe_mul(t, p.y, p.z);
  fe_double(o.z, t);                   // Z3 = 2*Y*Z
  return o;
}

static Jac jac_add(const Jac &p, const Jac &q) {
  if (jac_inf(p)) return q;
  if (jac_inf(q)) return p;
  U256 z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v, t;
  fe_sqr(z1z1, p.z);
  fe_sqr(z2z2, q.z);
  fe_mul(u1, p.x, z2z2);
  fe_mul(u2, q.x, z1z1);
  fe_mul(t, q.z, z2z2); fe_mul(s1, p.y, t);
  fe_mul(t, p.z, z1z1); fe_mul(s2, q.y, t);
  fe_sub(h, u2, u1);
  fe_sub(r, s2, s1);
  if (is_zero(h)) {
    if (is_zero(r)) return jac_double(p);
    return Jac{{0,0,0,0}, {0,0,0,0}, {0,0,0,0}};   // P + (-P) = infinity
  }
  fe_double(r, r);                     // r = 2*(S2-S1)
  fe_double(i, h); fe_sqr(i, i);       // I = (2H)^2
  fe_mul(j, h, i);                     // J = H*I
  fe_mul(v, u1, i);                    // V = U1*I
  Jac o;
  fe_sqr(t, r);
  fe_sub(t, t, j);
  U256 v2; fe_double(v2, v);
  fe_sub(o.x, t, v2);                  // X3 = r^2 - J - 2V
  fe_sub(t, v, o.x);
  fe_mul(t, r, t);                     // r*(V - X3)
  U256 s1j; fe_mul(s1j, s1, j); fe_double(s1j, s1j);
  fe_sub(o.y, t, s1j);                 // Y3 = r*(V-X3) - 2*S1*J
  fe_add(t, p.z, q.z); fe_sqr(t, t);
  fe_sub(t, t, z1z1); fe_sub(t, t, z2z2);
  fe_mul(o.z, t, h);                   // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*H
  return o;
}

// Jacobian -> affine (x, y). Returns false for the point at infinity.
static bool jac_to_affine(const Jac &p, U256 &x, U256 &y) {
  if (jac_inf(p)) return false;
  U256 zi, zi2, zi3, t;
  fe_inv(zi, p.z);
  fe_sqr(zi2, zi);
  fe_mul(zi3, zi2, zi);
  fe_mul(x, p.x, zi2);
  fe_mul(y, p.y, zi3);
  return true;
}

// k * P (double-and-add, MSB first)
static Jac jac_mul(const Jac &p, const U256 &k) {
  Jac r{{0,0,0,0}, {0,0,0,0}, {0,0,0,0}};   // infinity
  for (int i = 255; i >= 0; i--) {
    r = jac_double(r);
    if ((k.w[i >> 6] >> (i & 63)) & 1) r = jac_add(r, p);
  }
  return r;
}

static inline Jac generator() { return Jac{F_GX, F_GY, {{1, 0, 0, 0}}}; }

// ---------------- SHA-256 + HMAC (for RFC 6979) ----------------
struct Sha256 {
  uint32_t h[8];
  uint8_t buf[64];
  uint64_t len = 0;
  size_t n = 0;

  Sha256() { reset(); }
  void reset() {
    static const uint32_t iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                   0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    memcpy(h, iv, sizeof h); len = 0; n = 0;
  }
  static inline uint32_t ror(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }
  void block(const uint8_t *p) {
    static const uint32_t K[64] = {
      0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
      0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
      0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
      0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
      0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
      0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
      0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
      0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 | (uint32_t)p[i*4+2] << 8 | p[i*4+3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
      uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + S1 + ch + K[i] + w[i];
      uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
      uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = S0 + mj;
      hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
  }
  void update(const uint8_t *p, size_t l) {
    len += l;
    while (l) {
      size_t take = 64 - n; if (take > l) take = l;
      memcpy(buf + n, p, take); n += take; p += take; l -= take;
      if (n == 64) { block(buf); n = 0; }
    }
  }
  bytes final() {
    uint64_t bits = len * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t z = 0;
    while (n != 56) update(&z, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - i*8));
    update(lb, 8);
    bytes out(32);
    for (int i = 0; i < 8; i++) {
      out[i*4]   = (uint8_t)(h[i] >> 24); out[i*4+1] = (uint8_t)(h[i] >> 16);
      out[i*4+2] = (uint8_t)(h[i] >> 8);  out[i*4+3] = (uint8_t)h[i];
    }
    return out;
  }
};

static bytes hmac_sha256(const bytes &key, const bytes &msg) {
  uint8_t k[64]; memset(k, 0, sizeof k);
  if (key.size() > 64) { Sha256 s; s.update(key.data(), key.size()); bytes d = s.final(); memcpy(k, d.data(), d.size()); }
  else memcpy(k, key.data(), key.size());
  bytes inner, outer;
  for (int i = 0; i < 64; i++) { inner.push_back(k[i] ^ 0x36); outer.push_back(k[i] ^ 0x5c); }
  inner.insert(inner.end(), msg.begin(), msg.end());
  Sha256 si; si.update(inner.data(), inner.size()); bytes ih = si.final();
  outer.insert(outer.end(), ih.begin(), ih.end());
  Sha256 so; so.update(outer.data(), outer.size()); return so.final();
}

// ---------------- RFC 6979 nonce generator ----------------
struct Rfc6979 {
  bytes K, V;
  Rfc6979(const uint8_t key[32], const uint8_t h[32]) {
    K.assign(32, 0x00);
    V.assign(32, 0x01);
    bytes k(key, key + 32), m(h, h + 32), t;
    t = V; t.push_back(0x00); t.insert(t.end(), k.begin(), k.end()); t.insert(t.end(), m.begin(), m.end());
    K = hmac_sha256(K, t);
    V = hmac_sha256(K, V);
    t = V; t.push_back(0x01); t.insert(t.end(), k.begin(), k.end()); t.insert(t.end(), m.begin(), m.end());
    K = hmac_sha256(K, t);
    V = hmac_sha256(K, V);
  }
  // next candidate scalar k (big-endian bytes)
  bytes next() {
    for (;;) {
      V = hmac_sha256(K, V);
      U256 k;
      for (int i = 0; i < 4; i++) {
        u64 v = 0;
        for (int b = 0; b < 8; b++) v = (v << 8) | V[i*8 + b];
        k.w[3 - i] = v;
      }
      if (!is_zero(k) && cmp(k, F_N) < 0) {
        bytes out(32);
        for (int i = 0; i < 4; i++) for (int b = 0; b < 8; b++) out[i*8 + b] = (uint8_t)(k.w[3 - i] >> (56 - b*8));
        return out;
      }
      bytes t = V; t.push_back(0x00);
      K = hmac_sha256(K, t);
      V = hmac_sha256(K, V);
    }
  }
};

// ---------------- secp256k1 API (libsecp256k1-shaped) ----------------
struct PublicKey { U256 x, y; bool valid = false; };

static inline U256 bytes_to_u256(const uint8_t b[32]) {
  U256 v;
  for (int i = 0; i < 4; i++) {
    u64 w = 0;
    for (int k = 0; k < 8; k++) w = (w << 8) | b[i*8 + k];
    v.w[3 - i] = w;
  }
  return v;
}
static inline void u256_to_bytes(uint8_t out[32], const U256 &v) {
  for (int i = 0; i < 4; i++) for (int k = 0; k < 8; k++) out[i*8 + k] = (uint8_t)(v.w[3 - i] >> (56 - k*8));
}

static inline bool seckey_verify(const uint8_t key[32]) {
  U256 d = bytes_to_u256(key);
  return !is_zero(d) && cmp(d, F_N) < 0;
}

static bool pubkey_create(const uint8_t key[32], PublicKey &out) {
  if (!seckey_verify(key)) return false;
  Jac r = jac_mul(generator(), bytes_to_u256(key));
  if (!jac_to_affine(r, out.x, out.y)) return false;
  out.valid = true;
  return true;
}

// Deterministic ECDSA (RFC 6979) with low-S normalization.
// Returns r/s as big-endian 32-byte values and the recovery id (0..3).
static bool sign_recoverable(const uint8_t key[32], const uint8_t hash[32],
                             uint8_t r_out[32], uint8_t s_out[32], int &recid) {
  if (!seckey_verify(key)) return false;
  U256 d = bytes_to_u256(key);
  U256 z = bytes_to_u256(hash);
  if (cmp(z, F_N) >= 0) sub4(z.w, z.w, F_N.w);

  Rfc6979 kg(key, hash);
  for (int attempt = 0; attempt < 1000; attempt++) {
    bytes kb = kg.next();
    U256 k = bytes_to_u256(kb.data());
    Jac rj = jac_mul(generator(), k);
    U256 rx, ry;
    if (!jac_to_affine(rj, rx, ry)) continue;

    int rec = (ry.w[0] & 1) ? 1 : 0;
    if (cmp(rx, F_N) >= 0) rec |= 2;
    U256 r = rx;
    if (cmp(r, F_N) >= 0) sub4(r.w, r.w, F_N.w);
    if (is_zero(r)) continue;

    U256 kinv, rd, sum, s;
    sc_inv(kinv, k);
    sc_mul(rd, r, d);
    sc_add(sum, z, rd);
    sc_mul(s, kinv, sum);
    if (is_zero(s)) continue;
    if (sc_is_high(s)) {
      U256 t; sc_sub(t, F_N, s); s = t;
      rec ^= 1;
    }
    u256_to_bytes(r_out, r);
    u256_to_bytes(s_out, s);
    recid = rec;
    return true;
  }
  return false;
}

} // namespace ec
} // namespace pr
