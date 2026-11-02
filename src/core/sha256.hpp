#pragma once
// SHA-256 (FIPS 180-4), self-contained and pure (no Windows headers), used to identify the exact bytes
// of a policy file in reports. Identification only: it is not a signature and proves no authenticity.
#include <string>
#include <string_view>

namespace metasec {

// Lower-case hex, 64 characters.
std::string sha256_hex(std::string_view data);

}  // namespace metasec
