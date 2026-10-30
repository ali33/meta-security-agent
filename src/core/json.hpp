#pragma once
#include <string>
#include <string_view>

namespace metasec {

// Escapes `s` for use inside a JSON string literal (no surrounding quotes).
// Input is treated as UTF-8; invalid sequences are replaced with U+FFFD so the output is
// always valid UTF-8 and therefore valid JSON. Control characters become \u00XX.
std::string json_escape(std::string_view s);

}  // namespace metasec
