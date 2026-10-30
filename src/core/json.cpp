#include "json.hpp"

#include <cstdio>
#include <cstdlib>

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

const JsonValue* JsonValue::find(std::string_view key) const {
    if (type != Type::Object) return nullptr;
    for (const auto& kv : object)
        if (kv.first == key) return &kv.second;
    return nullptr;
}

namespace {

class Parser {
public:
    Parser(std::string_view t, std::size_t max_depth) : t_(t), max_depth_(max_depth) {}

    JsonParseResult run() {
        JsonParseResult r;
        skip_ws();
        if (!value(r.value, 0)) {
            r.error = err_;
            r.value = {};
            return r;
        }
        skip_ws();
        if (i_ != t_.size()) {
            r.error = "trailing characters after JSON value";
            r.value = {};
            return r;
        }
        r.ok = true;
        return r;
    }

private:
    std::string_view t_;
    std::size_t max_depth_;
    std::size_t i_ = 0;
    std::string err_;

    bool fail(const char* m) {
        if (err_.empty()) err_ = m;
        return false;
    }
    void skip_ws() {
        while (i_ < t_.size() && (t_[i_] == ' ' || t_[i_] == '\t' || t_[i_] == '\n' || t_[i_] == '\r')) ++i_;
    }
    bool lit(std::string_view w) {
        if (t_.substr(i_, w.size()) != w) return fail("invalid literal");
        i_ += w.size();
        return true;
    }

    bool value(JsonValue& v, std::size_t depth) {
        if (i_ >= t_.size()) return fail("unexpected end of JSON");
        const char c = t_[i_];
        if (c == '{' || c == '[') {
            if (depth + 1 > max_depth_) return fail("JSON nested too deeply");
            return c == '{' ? object(v, depth + 1) : array(v, depth + 1);
        }
        if (c == '"') {
            v.type = JsonValue::Type::String;
            return str(v.string);
        }
        if (c == 't') {
            v.type = JsonValue::Type::Bool;
            v.boolean = true;
            return lit("true");
        }
        if (c == 'f') {
            v.type = JsonValue::Type::Bool;
            return lit("false");
        }
        if (c == 'n') {
            v.type = JsonValue::Type::Null;
            return lit("null");
        }
        if (c == '-' || (c >= '0' && c <= '9')) return num(v);
        return fail("unexpected character in JSON");
    }

    bool num(JsonValue& v) {
        const std::size_t b = i_;
        if (t_[i_] == '-') ++i_;
        if (i_ >= t_.size()) return fail("invalid number");
        if (t_[i_] == '0') {
            ++i_;
        } else if (t_[i_] >= '1' && t_[i_] <= '9') {
            while (i_ < t_.size() && t_[i_] >= '0' && t_[i_] <= '9') ++i_;
        } else {
            return fail("invalid number");
        }
        bool integral = true;
        if (i_ < t_.size() && t_[i_] == '.') {
            integral = false;
            ++i_;
            const std::size_t d = i_;
            while (i_ < t_.size() && t_[i_] >= '0' && t_[i_] <= '9') ++i_;
            if (i_ == d) return fail("invalid number");
        }
        if (i_ < t_.size() && (t_[i_] == 'e' || t_[i_] == 'E')) {
            integral = false;
            ++i_;
            if (i_ < t_.size() && (t_[i_] == '+' || t_[i_] == '-')) ++i_;
            const std::size_t d = i_;
            while (i_ < t_.size() && t_[i_] >= '0' && t_[i_] <= '9') ++i_;
            if (i_ == d) return fail("invalid number");
        }
        const std::string text(t_.substr(b, i_ - b));
        v.type = JsonValue::Type::Number;
        v.number = std::strtod(text.c_str(), nullptr);
        if (integral && text.size() <= 18) {  // always fits int64
            v.is_integer = true;
            v.integer = std::strtoll(text.c_str(), nullptr, 10);
        }
        return true;
    }

    static int hex4(std::string_view s) {
        int v = 0;
        for (char c : s) {
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
            else return -1;
        }
        return v;
    }

    static void put_utf8(std::string& o, unsigned cp) {
        if (cp < 0x80) {
            o += static_cast<char>(cp);
        } else if (cp < 0x800) {
            o += static_cast<char>(0xC0 | (cp >> 6));
            o += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            o += static_cast<char>(0xE0 | (cp >> 12));
            o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            o += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            o += static_cast<char>(0xF0 | (cp >> 18));
            o += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            o += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    bool str(std::string& out) {
        ++i_;  // opening quote
        out.clear();
        while (i_ < t_.size()) {
            const unsigned char c = static_cast<unsigned char>(t_[i_]);
            if (c == '"') {
                ++i_;
                return true;
            }
            if (c < 0x20) return fail("control character in JSON string");
            if (c == '\\') {
                if (i_ + 1 >= t_.size()) break;
                const char e = t_[i_ + 1];
                i_ += 2;
                switch (e) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        if (i_ + 4 > t_.size()) return fail("invalid \\u escape");
                        int cp = hex4(t_.substr(i_, 4));
                        if (cp < 0) return fail("invalid \\u escape");
                        i_ += 4;
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (i_ + 6 > t_.size() || t_.substr(i_, 2) != "\\u") return fail("unpaired surrogate");
                            const int lo = hex4(t_.substr(i_ + 2, 4));
                            if (lo < 0xDC00 || lo > 0xDFFF) return fail("unpaired surrogate");
                            i_ += 6;
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            return fail("unpaired surrogate");
                        }
                        put_utf8(out, static_cast<unsigned>(cp));
                        break;
                    }
                    default: return fail("invalid escape in JSON string");
                }
                continue;
            }
            const std::size_t n = utf8_seq_len(t_, i_);
            if (n == 0) return fail("invalid UTF-8 in JSON string");
            out.append(t_.substr(i_, n));
            i_ += n;
        }
        return fail("unterminated JSON string");
    }

    bool array(JsonValue& v, std::size_t depth) {
        v.type = JsonValue::Type::Array;
        ++i_;
        skip_ws();
        if (i_ < t_.size() && t_[i_] == ']') {
            ++i_;
            return true;
        }
        for (;;) {
            skip_ws();
            JsonValue e;
            if (!value(e, depth)) return false;
            v.array.push_back(std::move(e));
            skip_ws();
            if (i_ >= t_.size()) return fail("unterminated JSON array");
            if (t_[i_] == ',') {
                ++i_;
                continue;
            }
            if (t_[i_] == ']') {
                ++i_;
                return true;
            }
            return fail("expected ',' or ']' in JSON array");
        }
    }

    bool object(JsonValue& v, std::size_t depth) {
        v.type = JsonValue::Type::Object;
        ++i_;
        skip_ws();
        if (i_ < t_.size() && t_[i_] == '}') {
            ++i_;
            return true;
        }
        for (;;) {
            skip_ws();
            if (i_ >= t_.size() || t_[i_] != '"') return fail("expected string key in JSON object");
            std::string key;
            if (!str(key)) return false;
            for (const auto& kv : v.object)
                if (kv.first == key) return fail("duplicate key in JSON object");
            skip_ws();
            if (i_ >= t_.size() || t_[i_] != ':') return fail("expected ':' in JSON object");
            ++i_;
            skip_ws();
            JsonValue e;
            if (!value(e, depth)) return false;
            v.object.emplace_back(std::move(key), std::move(e));
            skip_ws();
            if (i_ >= t_.size()) return fail("unterminated JSON object");
            if (t_[i_] == ',') {
                ++i_;
                continue;
            }
            if (t_[i_] == '}') {
                ++i_;
                return true;
            }
            return fail("expected ',' or '}' in JSON object");
        }
    }
};

}  // namespace

JsonParseResult json_parse(std::string_view text, std::size_t max_depth) { return Parser(text, max_depth).run(); }

}  // namespace metasec
