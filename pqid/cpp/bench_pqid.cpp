// bench_pqid.cpp — micro-benchmarks for the C++ reference implementation.
#include "pqid.hpp"
#include <chrono>
#include <cstdio>
#include <string>

template<typename F>
static void bench(const char* name, std::size_t n, F&& f) {
    for (int w = 0; w < 10000; w++) f();
    auto t0 = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < n; i++) f();
    auto t1 = std::chrono::steady_clock::now();
    double secs = std::chrono::duration<double>(t1 - t0).count();
    double ops = static_cast<double>(n) / secs;
    std::printf("  %-35s %12.0f ops/sec   (%6.0f ns/op)\n", name, ops, 1e9 / ops);
}

int main() {
    using namespace pqid;
    std::printf("PQID C++ benchmarks (g++ -O3, single thread)\n");
    std::printf("--------------------------------------------\n\n");

    StandardGenerator g;
    bench("Standard generation", 1'000'000, [&]() { (void)g.next(); });

    HLCGenerator h;
    bench("HLC generation (no observe)", 1'000'000, [&]() { (void)h.next(); });

    auto sample = g.next();
    bench("encode Base64URL",        5'000'000, [&]() { (void)encode_b64url(sample); });
    bench("encode Crockford Base32", 5'000'000, [&]() { (void)encode_crockford(sample); });

    auto enc_b64 = encode_b64url(sample);
    auto enc_b32 = encode_crockford(sample);
    bench("decode Base64URL",        5'000'000, [&]() { (void)decode_b64url(enc_b64); });
    bench("decode Crockford Base32", 5'000'000, [&]() { (void)decode_crockford(enc_b32); });
    return 0;
}
