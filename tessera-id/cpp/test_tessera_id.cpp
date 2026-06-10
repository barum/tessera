// test_tessera_id.cpp — test suite for the C++ reference implementation.
#include "tessera_id.hpp"

#include <iostream>
#include <set>
#include <string>

static int passes = 0, failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) { std::cout << "  ok  " << msg << '\n'; passes++; } \
    else      { std::cout << "  FAIL " << msg << '\n'; failures++; } \
} while (0)

int main() {
    using namespace tessera_id;

    std::cout << "TesseraID C++ reference test suite\n-----------------------------\n";

    // size & variant
    StandardGenerator g;
    auto id = g.next();
    CHECK(id.bytes.size() == kSize, "std TesseraID is 41 bytes");
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
    CHECK(seen.size() == 100'000, "100,000 std TesseraIDs are unique");

    // monotonic
    StandardGenerator g2;
    bool mono = true;
    auto prev = g2.next();
    for (int i = 0; i < 10'000; i++) {
        auto cur = g2.next();
        if (!(prev < cur)) { mono = false; break; }
        prev = cur;
    }
    CHECK(mono, "10,000 consecutive std TesseraIDs are strictly monotonic");

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

    // HLC drift rejection — typed as HLCDriftError (TID-00020)
    {
        HLCGenerator hg;
        std::uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        HLCObservation obs{now + 120'000, 0};
        bool threw = false;
        try { (void)hg.next(&obs); } catch (const HLCDriftError&) { threw = true; }
        CHECK(threw, "HLC rejects out-of-drift peer with HLCDriftError");
    }

    // unknown variant — typed as UnknownVariantError, still a TesseraIdError
    TesseraId bad{};
    bad.bytes[kVariantOffset] = 0x7F;
    bool threw_uv = false, base_caught = false;
    try { (void)validate(bad); } catch (const UnknownVariantError&) { threw_uv = true; }
    CHECK(threw_uv, "validate rejects unknown variant with UnknownVariantError");
    try { (void)validate(bad); } catch (const TesseraIdError&) { base_caught = true; }
    CHECK(base_caught, "UnknownVariantError is catchable as TesseraIdError");

    // string decoders reject unknown variants 0x00/0x05/0xFF (TID-00020)
    {
        bool b64_reject = true, b32_reject = true;
        for (std::uint8_t v : {std::uint8_t{0x00}, std::uint8_t{0x05}, std::uint8_t{0xFF}}) {
            TesseraId raw{};
            raw.bytes[0] = 0x01; raw.bytes[1] = 0x8B;
            raw.bytes[kVariantOffset] = v;
            bool threw64 = false, threw32 = false;
            try { (void)decode_b64url(encode_b64url(raw)); }
            catch (const UnknownVariantError&) { threw64 = true; }
            try { (void)decode_crockford(encode_crockford(raw)); }
            catch (const UnknownVariantError&) { threw32 = true; }
            if (!threw64) b64_reject = false;
            if (!threw32) b32_reject = false;
        }
        CHECK(b64_reject, "decode_b64url rejects variants 0x00/0x05/0xFF");
        CHECK(b32_reject, "decode_crockford rejects variants 0x00/0x05/0xFF");
    }

    // malformed text throws InvalidEncodingError (TID-00020 taxonomy)
    {
        bool len_typed = false, char_typed = false, pad_typed = false;
        try { (void)decode_b64url("tooshort"); }
        catch (const InvalidEncodingError&) { len_typed = true; }
        CHECK(len_typed, "decode_b64url wrong length throws InvalidEncodingError");
        std::string badchar = encode_b64url(g.next());
        badchar[0] = '!';
        try { (void)decode_b64url(badchar); }
        catch (const InvalidEncodingError&) { char_typed = true; }
        CHECK(char_typed, "decode_b64url invalid char throws InvalidEncodingError");
        std::string padded = encode_b64url(g.next());
        padded[54] = 'B';  // non-zero low pad bits in final char
        try { (void)decode_b64url(padded); }
        catch (const InvalidEncodingError&) { pad_typed = true; }
        CHECK(pad_typed, "decode_b64url non-zero pad bits throws InvalidEncodingError");
    }

    // HLC drift bound is clamped (TID-00020)
    {
        HLCGenerator hg;
        bool relax_rejected = false;
        try { hg.set_max_drift_ms(kHLCDefaultDriftMs + 1); }
        catch (const std::invalid_argument&) { relax_rejected = true; }
        CHECK(relax_rejected, "set_max_drift_ms rejects relaxed (>60s) bound");

        // Stricter bound is honored: peer 5s ahead vs 1s bound.
        hg.set_max_drift_ms(1'000);
        std::uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        HLCObservation near_obs{now + 5'000, 0};
        bool strict_threw = false;
        try { (void)hg.next(&near_obs); } catch (const HLCDriftError&) { strict_threw = true; }
        CHECK(strict_threw, "stricter (1s) drift bound rejects peer 5s ahead");

        // 0 selects the default bound: peer 100ms ahead accepted again.
        hg.set_max_drift_ms(0);
        HLCObservation ok_obs{now + 100, 0};
        bool default_ok = true;
        try { (void)hg.next(&ok_obs); } catch (const TesseraIdError&) { default_ok = false; }
        CHECK(default_ok, "drift bound 0 selects default (accepts peer 100ms ahead)");
    }

    std::cout << '\n' << passes << " passed, " << failures << " failed.\n";
    return failures == 0 ? 0 : 1;
}
