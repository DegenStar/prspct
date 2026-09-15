// Emits test vectors for the bundled secp256k1 signer + keccak/RLP/tx code.
// Verifier: tests/test_crypto.py (independent Python implementation).
//
//   clang++ -O2 -std=c++17 -I.. -o crypto_selftest crypto_selftest.cpp -lcurl
//   ./crypto_selftest | python3 test_crypto.py
#include "../prspct_tx.h"
#include <cstdarg>
#include <cinttypes>
#include <random>

using namespace pr;

static void put(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}

static std::string to_hex(const ec::U256 &v, size_t bytes = 32) {
  uint8_t buf[32];
  ec::u256_to_bytes(buf, v);
  static const char *d = "0123456789abcdef";
  std::string s;
  for (size_t i = 32 - bytes; i < 32; i++) { s += d[buf[i] >> 4]; s += d[buf[i] & 15]; }
  return s;
}

int main() {
  // ---- keccak-256 + sha256 anchors ----
  bytes e = keccak256((const uint8_t *)"", 0);
  bytes abc = keccak256((const uint8_t *)"abc", 3);
  bytes sel = selector_claim();
  put("keccak %s %s\n", hex(e, false).c_str(), hex(abc, false).c_str());
  put("selector %s\n", hex(sel, false).c_str());

  {
    const char *msgs[] = {"", "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    for (const char *m : msgs) {
      ec::Sha256 s; s.update((const uint8_t *)m, strlen(m));
      put("sha256 %s %s\n", hex(s.final(), false).c_str(), m);
    }
    // one million 'a'
    ec::Sha256 s; uint8_t chunk[1000]; memset(chunk, 'a', sizeof chunk);
    for (int i = 0; i < 1000; i++) s.update(chunk, sizeof chunk);
    put("sha256 %s <1e6 a>\n", hex(s.final(), false).c_str());
  }

  // ---- field / scalar arithmetic vectors ----
  std::mt19937_64 rng(0x50525350'43540001ULL);
  auto rand_u256 = [&](const ec::U256 &mod) {
    ec::U256 v;
    do {
      for (int i = 0; i < 4; i++) v.w[i] = rng();
      for (int i = 0; i < 4; i++) {   // squeeze into range by masking off high bits
        int bits = (i == 3) ? 63 : 64;
        (void)bits;
      }
    } while (ec::cmp(v, mod) >= 0);
    return v;
  };

  for (int i = 0; i < 200; i++) {
    ec::U256 a = rand_u256(ec::F_P), b = rand_u256(ec::F_P), r;
    ec::fe_add(r, a, b); put("fe add %s %s %s\n", to_hex(a).c_str(), to_hex(b).c_str(), to_hex(r).c_str());
    ec::fe_sub(r, a, b); put("fe sub %s %s %s\n", to_hex(a).c_str(), to_hex(b).c_str(), to_hex(r).c_str());
    ec::fe_mul(r, a, b); put("fe mul %s %s %s\n", to_hex(a).c_str(), to_hex(b).c_str(), to_hex(r).c_str());
    if (i < 8) {
      ec::U256 ai; ec::fe_inv(ai, a);
      put("fe inv %s %s\n", to_hex(a).c_str(), to_hex(ai).c_str());
    }
  }
  for (int i = 0; i < 60; i++) {
    ec::U256 a = rand_u256(ec::F_N), b = rand_u256(ec::F_N), r;
    ec::sc_add(r, a, b); put("sc add %s %s %s\n", to_hex(a).c_str(), to_hex(b).c_str(), to_hex(r).c_str());
    ec::sc_sub(r, a, b); put("sc sub %s %s %s\n", to_hex(a).c_str(), to_hex(b).c_str(), to_hex(r).c_str());
    ec::sc_mul(r, a, b); put("sc mul %s %s %s\n", to_hex(a).c_str(), to_hex(b).c_str(), to_hex(r).c_str());
    if (i < 5) {
      ec::U256 ai; ec::sc_inv(ai, a);
      put("sc inv %s %s\n", to_hex(a).c_str(), to_hex(ai).c_str());
      put("sc ishigh %s %d\n", to_hex(a).c_str(), ec::sc_is_high(a) ? 1 : 0);
    }
  }

  // ---- point arithmetic: k*G for small/structured scalars ----
  {
    ec::U256 ks[6] = {};
    ks[0].w[0] = 1; ks[1].w[0] = 2; ks[2].w[0] = 7;
    ks[3].w[0] = 0xFFFFFFFFFFFFFFFFULL; ks[3].w[1] = 0xFFFFFFFFFFFFFFFFULL;
    ks[4] = ec::F_N; ks[4].w[0] -= 1;                     // n-1 => -G
    ks[5].w[0] = 0x123456789ULL; ks[5].w[3] = 0x8000000000000000ULL;
    for (auto &k : ks) {
      ec::Jac p = ec::jac_mul(ec::generator(), k);
      ec::U256 x, y;
      if (!ec::jac_to_affine(p, x, y)) { put("mulgen %s inf inf\n", to_hex(k).c_str()); continue; }
      put("mulgen %s %s %s\n", to_hex(k).c_str(), to_hex(x).c_str(), to_hex(y).c_str());
    }
  }

  // ---- wallet addresses (known vectors) ----
  struct { const char *key; const char *note; } keys[] = {
    {"0x0000000000000000000000000000000000000000000000000000000000000001", "privkey 1"},
    {"0x4646464646464646464646464646464646464646464646464646464646464646", "rfc6979-ish"},
    {"0x00000000000000000000000000000000000000000000000000000000cafebabe", "small"},
  };
  Wallet w;
  for (auto &k : keys) {
    if (!w.init(k.key)) { put("addr %s ERR\n", k.key); continue; }
    put("addr %s %s\n", k.key, hex(w.address, false).c_str());
  }

  // ---- signatures ----
  for (int i = 0; i < 12; i++) {
    uint8_t key[32], msg[32];
    for (int j = 0; j < 32; j++) { key[j] = (uint8_t)rng(); msg[j] = (uint8_t)rng(); }
    key[0] = (uint8_t)(rng() & 0x7f);   // keep well below n
    if (!ec::seckey_verify(key)) { i--; continue; }
    uint8_t rb[32], sb[32]; int recid = 0;
    bool ok = ec::sign_recoverable(key, msg, rb, sb, recid);
    bytes kh(key, key + 32), mh(msg, msg + 32);
    put("sig %s %s %d %s %s %s\n", ok ? "1" : "0", hex(kh, false).c_str(), recid,
        hex(bytes(rb, rb + 32), false).c_str(), hex(bytes(sb, sb + 32), false).c_str(),
        hex(mh, false).c_str());
  }

  // ---- full claim tx ----
  {
    const char *privs[] = {"0x0000000000000000000000000000000000000000000000000000000000000001",
                           "0x0000000000000000000000000000000000000000000000000000000000000002",
                           "0x5fb2bc0cd0d5e72b4d0c4b5fd0a5a3a1d4e4f2b6d1b9b8d3dc4ca0b4f8ac9de1"};
    uint64_t nonces[] = {1, 0xdeadbeefULL, 0xffffffffffffffffULL};
    for (int i = 0; i < 3; i++) {
      Wallet tw;
      if (!tw.init(privs[i])) { put("tx %s ERR\n", privs[i]); continue; }
      TxParams p;
      unhex("0xd078008c3D887A52CE722A3cA0539cA1F4971dD1", p.to);
      p.tx_nonce = 7 + i;
      p.max_fee_wei = (i == 1) ? "1500000000" : "42";
      p.tip_wei = (i == 2) ? "100000000" : "0";
      p.chain_id = 4663;
      bytes raw, th;
      if (!build_claim_tx(tw, p, nonces[i], raw, th)) { put("tx %s ERR\n", privs[i]); continue; }

      // re-derive the unsigned payload + signing hash exactly as build_claim_tx does,
      // so the Python side can diff field-by-field when something disagrees
      bytes data = selector_claim();
      bytes n32 = pad32(u64_to_be(nonces[i]));
      data.insert(data.end(), n32.begin(), n32.end());
      std::vector<bytes> f = {
        rlp_bytes(u64_to_be(p.chain_id)), rlp_bytes(u64_to_be(p.tx_nonce)),
        rlp_bytes(dec_to_be(p.tip_wei)), rlp_bytes(dec_to_be(p.max_fee_wei)),
        rlp_bytes(u64_to_be(p.gas_limit)), rlp_bytes(p.to), rlp_bytes(bytes()),
        rlp_bytes(data), rlp_list({}),
      };
      bytes unsigned_payload = rlp_list(f);
      bytes sh; sh.push_back(0x02); sh.insert(sh.end(), unsigned_payload.begin(), unsigned_payload.end());
      bytes shash = keccak256(sh);
      put("tx %s %s %llu %s %s %s %s %llu %s %s\n", privs[i], hex(tw.address, false).c_str(),
          (unsigned long long)nonces[i], p.max_fee_wei.c_str(), p.tip_wei.c_str(),
          hex(raw, false).c_str(), hex(th, false).c_str(), (unsigned long long)p.tx_nonce,
          hex(unsigned_payload, false).c_str(), hex(shash, false).c_str());
    }
  }

  // ---- claim hash shape: template+nonce must equal keccak(seed||sender||nonce) ----
  {
    // isolated sign of the exact tx-1 digest, to compare against the tx path
    {
      const char *priv = "0x0000000000000000000000000000000000000000000000000000000000000001";
      const char *digest = "00820e3ba01b499e2c13c6d92955e0e811e0a51d36000e825f87c33933e31e63";
      Wallet tw; tw.init(priv);
      bytes hb; unhex(digest, hb);
      uint8_t rb[32], sb[32]; int recid = 0;
      bool ok = ec::sign_recoverable(tw.key, hb.data(), rb, sb, recid);
      put("txsig %s %d %s %s\n", ok ? "1" : "0", recid,
          hex(bytes(rb, rb + 32), false).c_str(), hex(bytes(sb, sb + 32), false).c_str());
      bytes r2, s2; int v2 = 0;
      bool ok2 = tw.sign(hb, r2, s2, v2);
      put("walletsig %s %d %s %s\n", ok2 ? "1" : "0", v2, hex(r2, false).c_str(), hex(s2, false).c_str());
    }

    uint8_t seed[32], sender[20];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x11 + i);
    for (int i = 0; i < 20; i++) sender[i] = (uint8_t)(0xa0 + i);
    uint64_t nonce = 0x0123456789abcdefULL;
    bytes buf(seed, seed + 32);
    buf.insert(buf.end(), sender, sender + 20);
    for (int i = 0; i < 32; i++) buf.push_back(i >= 24 ? (uint8_t)(nonce >> (8 * (31 - i))) : 0);
    bytes h = keccak256(buf);
    put("claimhash %s %s %016llx %s\n", hex(bytes(seed, seed + 32), false).c_str(),
        hex(bytes(sender, sender + 20), false).c_str(), (unsigned long long)nonce, hex(h, false).c_str());
  }
  return 0;
}
