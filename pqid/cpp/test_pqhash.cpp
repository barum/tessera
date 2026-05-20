// Smoke tests for the C++ PQHash header.
#include "pqhash.hpp"

#include <cstring>
#include <iostream>
#include <string>

static int fail = 0;
static void check(bool ok, const char* msg) {
    std::cout << "  " << (ok ? "ok " : "FAIL") << " " << msg << "\n";
    if (!ok) fail++;
}

int main() {
    using namespace pqhash;

    // Size
    Generator g;
    Pqhash h = g.next("hello");
    check(h.bytes.size() == 73, "size = 73");
    check(h.bytes[6] == 0x03, "variant = 0x03");

    // Determinism
    auto t1 = hash_only("hello, world");
    Generator g2;
    auto h2 = g2.next("hello, world");
    check(std::memcmp(t1.data(), h2.bytes.data() + 9, 64) == 0,
          "stateless hash_only matches generator tail");

    // hash_at deterministic
    auto p = hash_at("hello", 1'700'000'000'000ULL, 1);
    check(detail::get_be48(p.bytes.data()) == 1'700'000'000'000ULL, "hash_at ts");
    check(detail::get_be16(p.bytes.data() + 7) == 1, "hash_at counter");

    // verify
    check(verify(p, "hello"), "verify(correct)");
    check(!verify(p, "hellO"), "verify(wrong)");

    // Round-trip
    auto s64 = encode_b64url(p);
    check(s64.size() == 98, "b64 length 98");
    auto p2 = decode_b64url(s64);
    check(std::memcmp(p.bytes.data(), p2.bytes.data(), 73) == 0, "b64 roundtrip");

    auto s32 = encode_crockford(p);
    check(s32.size() == 117, "crockford length 117");
    auto p3 = decode_crockford(s32);
    check(std::memcmp(p.bytes.data(), p3.bytes.data(), 73) == 0, "crockford roundtrip");

    // Cross-rejection: PQID byte 6 != 0x03 must throw.
    p.bytes[6] = 0x01;
    bool threw = false;
    try { (void)decode(p); } catch (const PqhashError&) { threw = true; }
    check(threw, "decode rejects non-0x03 variant");

    if (fail) {
        std::cout << "\n" << fail << " test(s) failed.\n";
        return 1;
    }
    std::cout << "\nAll C++ PQHash smoke tests passed.\n";
    return 0;
}
