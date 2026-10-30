#include "json.hpp"

#include <cstdio>

namespace metasec {

namespace {

// Returns the length of the valid UTF-8 sequence starting at s[i], or 0 if invalid.
// Rejects overlongs, surrogates and code points above U+10FFFF.
std::size_t utf8_seq_len(std::string_view s, std::size_t i) {
    const auto b = [&](std::size_t k) { return static_cast<unsigned char>(s[k]); };
    const unsigned char c = b(i);
    const std::size_t left = s.size() - i;
    auto cont = [&](std::size_t k) { return (b(i + k) & 0xC0) == 0x80; };
    if (c < 0x80) return 1;
    if (c >= 0xC2 && c <= 0xDF) return (left >= 2 && cont(1)) ? 2 : 0;
    if (c >= 0xE0 && c <= 0xEF) {
        if (left < 3 || !cont(1) || !cont(2)) return 0;
        if (c == 0xE0 && b(i + 1) < 0xA0) return 0;   // overlong
        if (c == 0xED && b(i + 1) >= 0xA0) return 0;  // surrogate
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (left < 4 || !cont(1) || !cont(2) || !cont(3)) return 0;
        if (c == 0xF0 && b(i + 1) < 0x90) return 0;   // overlong
        if (c == 0xF4 && b(i + 1) >= 0x90) return 0;  // > U+10FFFF
        return 4;
    }
    return 0;
}

}  // namespace

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (std::size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20 || c == 0x7F) {
                        char buf[8];
                        std::snprintf(buf, sizeof buf, "\\u%04x", c);
                        out += buf;
                    } else {
                        out += static_cast<char>(c);
                    }
            }
            ++i;
            continue;
        }
        const std::size_t n = utf8_seq_len(s, i);
        if (n == 0) {
            out += "\\ufffd";
            ++i;
        } else {
            out.append(s.substr(i, n));
            i += n;
        }
    }
    return out;
}

}  // namespace metasec
