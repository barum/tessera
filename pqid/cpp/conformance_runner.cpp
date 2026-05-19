// C++ conformance runner. Usage: conformance_runner <vectors.json>
//
// Uses a tiny string-search JSON reader (records have a fixed schema, so a
// real parser is overkill). The C runner uses the same approach.

#include "pqid.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>

using namespace pqid;

static std::string slurp(const char* path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Find next top-level JSON object in `s` starting at `pos`. Returns
// (begin, end) indices into s with end exclusive past the closing '}'.
// Returns std::nullopt if no more objects.
static std::optional<std::pair<size_t, size_t>> next_record(const std::string& s, size_t& pos) {
    while (pos < s.size() && s[pos] != '{' && s[pos] != ']') ++pos;
    if (pos >= s.size() || s[pos] == ']') return std::nullopt;
    size_t begin = pos;
    int depth = 0; bool in_str = false; bool escape = false;
    for (; pos < s.size(); ++pos) {
        char c = s[pos];
        if (escape) { escape = false; continue; }
        if (in_str) {
            if (c == '\\') escape = true;
            else if (c == '"') in_str = false;
        } else {
            if (c == '"') in_str = true;
            else if (c == '{') ++depth;
            else if (c == '}') {
                --depth;
                if (depth == 0) { ++pos; return std::make_pair(begin, pos); }
            }
        }
    }
    return std::nullopt;
}

static std::optional<std::string> get_str(const std::string& rec, const std::string& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch m;
    if (std::regex_search(rec, m, re)) return m[1].str();
    return std::nullopt;
}

static std::optional<int64_t> get_int(const std::string& rec, const std::string& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*(-?\\d+)");
    std::smatch m;
    if (std::regex_search(rec, m, re)) return std::stoll(m[1].str());
    return std::nullopt;
}

// Extract a nested field from "obj_key": { ..., "int_key": N, ... }
static std::optional<int64_t> get_nested_int(const std::string& rec,
                                             const std::string& obj_key,
                                             const std::string& int_key) {
    std::regex outer("\"" + obj_key + "\"\\s*:\\s*\\{([^{}]*)\\}");
    std::smatch m;
    if (!std::regex_search(rec, m, outer)) return std::nullopt;
    return get_int(m[1].str(), int_key);
}

static std::optional<std::string> get_nested_str(const std::string& rec,
                                                 const std::string& obj_key,
                                                 const std::string& str_key) {
    std::regex outer("\"" + obj_key + "\"\\s*:\\s*\\{([^{}]*)\\}");
    std::smatch m;
    if (!std::regex_search(rec, m, outer)) return std::nullopt;
    return get_str(m[1].str(), str_key);
}

static bool has_null_field(const std::string& rec, const std::string& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*null");
    return std::regex_search(rec, re);
}

static std::vector<uint8_t> hex_to_bytes(const std::string& h) {
    std::vector<uint8_t> out(h.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(std::stoul(h.substr(2 * i, 2), nullptr, 16));
    }
    return out;
}

static std::string bytes_to_hex(const uint8_t* p, size_t n) {
    std::string out(n * 2, '\0');
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 0xF];
    }
    return out;
}

struct Result { bool ok; std::string detail; };

static Result op_decode(const std::string& rec) {
    auto hex = get_str(rec, "input_hex");
    if (!hex) return {false, "no input_hex"};
    auto raw = hex_to_bytes(*hex);
    if (raw.size() != kSize) return {false, "bad len"};
    Pqid p;
    std::memcpy(p.bytes.data(), raw.data(), kSize);
    auto want_variant = get_nested_int(rec, "expected", "variant").value_or(-1);
    auto want_ts      = get_nested_int(rec, "expected", "timestamp_ms").value_or(-1);
    auto want_ctr     = get_nested_int(rec, "expected", "counter").value_or(-1);
    auto want_rand    = get_nested_str(rec, "expected", "random_hex").value_or("");
    if (p.bytes[kVariantOffset] != want_variant)
        return {false, "variant mismatch"};
    int64_t ts = (int64_t)detail::get_be48(p.bytes.data());
    if (ts != want_ts) return {false, "ts mismatch"};
    int64_t ctr = ((int64_t)p.bytes[kCounterOffset] << 8) | p.bytes[kCounterOffset + 1];
    if (ctr != want_ctr) return {false, "counter mismatch"};
    auto got_rand = bytes_to_hex(p.bytes.data() + kRandomOffset, kRandomBytes);
    if (got_rand != want_rand) return {false, "random got=" + got_rand + " want=" + want_rand};
    return {true, ""};
}

static Result op_encode_b64(const std::string& rec) {
    auto hex = get_str(rec, "input_hex");
    auto want = get_str(rec, "expected_str");
    if (!hex || !want) return {false, "missing fields"};
    auto raw = hex_to_bytes(*hex);
    Pqid p; std::memcpy(p.bytes.data(), raw.data(), kSize);
    auto s = encode_b64url(p);
    if (s != *want) return {false, "got=" + s + " want=" + *want};
    return {true, ""};
}

static Result op_decode_b64(const std::string& rec) {
    auto in = get_str(rec, "input_str");
    auto want = get_str(rec, "expected_hex");
    if (!in || !want) return {false, "missing fields"};
    try {
        auto p = decode_b64url(*in);
        auto got = bytes_to_hex(p.bytes.data(), kSize);
        if (got != *want) return {false, "got=" + got + " want=" + *want};
    } catch (const std::exception& e) {
        return {false, std::string("error: ") + e.what()};
    }
    return {true, ""};
}

static Result op_encode_crockford(const std::string& rec) {
    auto hex = get_str(rec, "input_hex");
    auto want = get_str(rec, "expected_str");
    if (!hex || !want) return {false, "missing fields"};
    auto raw = hex_to_bytes(*hex);
    Pqid p; std::memcpy(p.bytes.data(), raw.data(), kSize);
    auto s = encode_crockford(p);
    if (s != *want) return {false, "got=" + s + " want=" + *want};
    return {true, ""};
}

static Result op_decode_crockford(const std::string& rec) {
    auto in = get_str(rec, "input_str");
    auto want = get_str(rec, "expected_hex");
    if (!in || !want) return {false, "missing fields"};
    try {
        auto p = decode_crockford(*in);
        auto got = bytes_to_hex(p.bytes.data(), kSize);
        if (got != *want) return {false, "got=" + got + " want=" + *want};
    } catch (const std::exception& e) {
        return {false, std::string("error: ") + e.what()};
    }
    return {true, ""};
}

static Result op_validate_invalid(const std::string& rec) {
    auto kind = get_str(rec, "input_kind").value_or("");
    try {
        if (kind == "binary_hex") {
            auto hex = get_str(rec, "input_hex").value_or("");
            if (hex.size() != 2 * kSize) return {true, ""};
            auto raw = hex_to_bytes(hex);
            uint8_t v = raw[kVariantOffset];
            if (v != kVariantStandard && v != kVariantHLC) {
                throw PqidError("UnknownVariant");
            }
            return {false, "expected error, got success"};
        } else if (kind == "b64") {
            auto s = get_str(rec, "input_str").value_or("");
            decode_b64url(s);
            return {false, "expected error, got success"};
        } else if (kind == "crockford") {
            auto s = get_str(rec, "input_str").value_or("");
            decode_crockford(s);
            return {false, "expected error, got success"};
        }
    } catch (const std::exception&) {
        return {true, ""};
    }
    return {false, "unknown input_kind " + kind};
}

static Result op_hlc_overflow(const std::string& rec) {
    auto l_old = get_nested_int(rec, "start", "l_old");
    auto c_old = get_nested_int(rec, "start", "c_old");
    auto pt = get_int(rec, "physical_time_ms");
    auto exp_l = get_nested_int(rec, "expected", "l_new");
    auto exp_c = get_nested_int(rec, "expected", "c_new");
    if (!l_old || !c_old || !pt || !exp_l || !exp_c)
        return {false, "missing fields"};

    HLCGenerator g;
    g.set_state_for_testing(*l_old, static_cast<uint16_t>(*c_old));
    set_now_ms_for_testing(*pt);

    Pqid out;
    try {
        if (has_null_field(rec, "observe")) {
            out = g.next();
        } else {
            auto l_msg = get_nested_int(rec, "observe", "l_msg");
            auto c_msg = get_nested_int(rec, "observe", "c_msg");
            if (!l_msg || !c_msg) {
                set_now_ms_for_testing(UINT64_MAX);
                return {false, "no observe.l_msg/c_msg"};
            }
            HLCObservation obs{static_cast<uint64_t>(*l_msg),
                               static_cast<uint16_t>(*c_msg)};
            out = g.next(&obs);
        }
    } catch (const std::exception& e) {
        set_now_ms_for_testing(UINT64_MAX);
        return {false, std::string("exception: ") + e.what()};
    }
    set_now_ms_for_testing(UINT64_MAX);
    int64_t got_l = (int64_t)detail::get_be48(out.bytes.data());
    int64_t got_c = ((int64_t)out.bytes[kCounterOffset] << 8) | out.bytes[kCounterOffset + 1];
    if (got_l != *exp_l || got_c != *exp_c) {
        std::ostringstream e;
        e << "got=(l=" << got_l << ", c=" << got_c << ") want=(l=" << *exp_l << ", c=" << *exp_c << ")";
        return {false, e.str()};
    }
    return {true, ""};
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: conformance_runner <vectors.json>\n");
        return 2;
    }
    auto data = slurp(argv[1]);
    if (data.empty()) { std::perror("slurp"); return 2; }

    size_t pos = data.find('[');
    if (pos == std::string::npos) { std::fprintf(stderr, "no array\n"); return 2; }

    int failures = 0;
    while (auto range = next_record(data, pos)) {
        std::string rec = data.substr(range->first, range->second - range->first);
        auto name = get_str(rec, "name").value_or("?");
        auto op = get_str(rec, "op").value_or("?");
        if (name == "doc") continue;

        Result r{false, "unknown op " + op};
        if      (op == "decode")            r = op_decode(rec);
        else if (op == "encode_b64")        r = op_encode_b64(rec);
        else if (op == "decode_b64")        r = op_decode_b64(rec);
        else if (op == "encode_crockford")  r = op_encode_crockford(rec);
        else if (op == "decode_crockford")  r = op_decode_crockford(rec);
        else if (op == "validate_invalid")  r = op_validate_invalid(rec);
        else if (op == "hlc_overflow")      r = op_hlc_overflow(rec);

        if (r.ok) std::printf("PASS %s\n", name.c_str());
        else { std::printf("FAIL %s %s\n", name.c_str(), r.detail.c_str()); ++failures; }
    }
    return failures > 0 ? 1 : 0;
}
