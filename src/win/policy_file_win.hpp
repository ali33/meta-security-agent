#pragma once
#include <string>

namespace metasec::win {

struct PolicyFileRead {
    bool ok = false;
    std::string content;  // the file's bytes (at most kMaxPolicyBytes) when ok
    std::string error;    // short reason when !ok; never contains the path
};

// Reads a local policy file, read-only, bounded. Refuses: anything that is not a regular disk file
// (directory, console, pipe, NUL), a file on a network share (checked on the opened handle, so a mapped
// drive or a symlink to a share is caught too), a file larger than kMaxPolicyBytes (checked before and
// during the read), and a path that is not valid UTF-8. No network, no write, no execution.
PolicyFileRead read_policy_file(const std::string& utf8_path);

}  // namespace metasec::win
