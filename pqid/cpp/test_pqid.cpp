// test_pqid.cpp — test suite for the C++ reference implementation.
#include "pqid.hpp"

#include <iostream>
#include <set>
#include <string>

static int passes = 0, failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) { std::cout << "  ok  " << msg << '\n'; passes++; } \
    else      { std::cout << "  FAIL " << msg << '\n'; failures++; } \
} while (0)

int main() {
    using namespace pqid;

    std::cout << "PQID C++ reference test suite\n-----------------------------\n";

    // size & variant
    StandardGenerator g;
    auto id = g.next();
    CHECK(id.bytes.size() == kSize, "std PQID is 41 bytes");
    CHECK(id.variant() == kVariantStandard, "std variant byte");

    HLCGenerator h;
    auto hid = h.next();
    CHECK(hid.variant() == kVariantHLC, "hlc variant byte");

    // 100k unique
    std::set<std::string> seen;
    for (int i = 0; i < 100'000; i++) {
        auto p = g.next();
        seen.insert(std::string(reinterpret_cast<const char*>(p.bytes.data()), kSize));
    }
    CHECK(seen.size() == 100'000, "100,000 std PQIDs are unique");

    // monotonic
    StandardGenerator g2;
    bool mono = true;
    auto prev = g2.next();
    for (int i = 0; i < 10'000; i++) {
        auto cur = g2.next();
        if (!(prev < cur)) { mono = false; break; }
        prev = cur;
    }
    CHECK(mono, "10,000 consecutive std PQIDs are strictly monotonic");

    // round-trips
    bool b64ok = true;
    for (int i = 0; i < 100; i++) {
        auto p = g.next();
        if (decode_b64url(encode_b64url(p)) != p) { b64ok = false; break; }
    }
    CHECK(b64ok, "B64URL round-trip on 100 fresh IDs");

    bool b32ok = true;
    for (int i = 0; i < 100; i++) {
        auto p = g.next();
        if (decode_crockford(encode_crockford(p)) != p) { b32ok = false; break; }
    }
    CHECK(b32ok, "Crockford round-trip on 100 fresh IDs");

    // Crockford ASCII sort matches byte sort
    std::string prev_b32;
    bool sort_ok = true;
    for (int i = 0; i < 200; i++) {
        auto cur = g.next();
        auto enc = encode_crockford(cur);
        if (i > 0 && !(prev_b32 < enc)) { sort_ok = false; break; }
        prev_b32 = enc;
    }
    CHECK(sort_ok, "Crockford ASCII sort matches generation order");

    // HLC observation accepted
    {
        HLCGenerator hg;
        std::uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        HLCObservation obs{now + 100, 0};
        auto p = hg.next(&obs);
        CHECK(p.timestamp_ms() >= now + 100, "HLC adopts in-bound peer time");
    }

    // HLC drift rejection
    {
        HLCGenerator hg;
        std::uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        HLCObservation obs{now + 120'000, 0};
        bool threw = false;
        try { hg.next(&obs); } catch (const PqidError&) { threw = true; }
        CHECK(threw, "HLC rejects out-of-drift peer");
    }

    // unknown variant
    Pqid bad{};
    bad.bytes[kVariantOffset] = 0x7F;
    bool threw_uv = false;
    try { validate(bad); } catch (const PqidError&) { threw_uv = true; }
    CHECK(threw_uv, "validate rejects unknown variant");

    std::cout << '\n' << passes << " passed, " << failures << " failed.\n";
    return failures == 0 ? 0 : 1;
}
