#pragma once
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace metasec {

// Escapes `s` for use inside a JSON string literal (no surrounding quotes).
// Input is treated as UTF-8; invalid sequences are replaced with U+FFFD so the output is
// always valid UTF-8 and therefore valid JSON. Control characters become \u00XX.
std::string json_escape(std::string_view s);

// --- strict parser (used to validate untrusted IPC replies and stored rows) ------------------
// RFC 8259 subset: no comments, no trailing commas, no trailing garbage, no duplicate object keys,
// strings must be valid UTF-8 without raw control characters, nesting limited to `max_depth`.
struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };
    Type type = Type::Null;
    bool boolean = false;
    bool is_integer = false;  // Number written without fraction/exponent and fitting int64
    long long integer = 0;
    double number = 0;
    std::string string;
    std::vector<JsonValue> array;
    std::vector<std::pair<std::string, JsonValue>> object;

    // Member of an Object by exact key, or nullptr.
    const JsonValue* find(std::string_view key) const;
};

struct JsonParseResult {
    bool ok = false;
    std::string error;  // short, never echoes the input
    JsonValue value;
};

JsonParseResult json_parse(std::string_view text, std::size_t max_depth = 16);

}  // namespace metasec
