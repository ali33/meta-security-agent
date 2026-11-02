#pragma once
#include <string>

namespace metasec::win {

struct PolicyFileRead {
    bool ok = false;
    std::string content;  // the file's bytes (at most kMaxPolicyBytes) when ok
    std::string error;    // short reason when !ok; never contains the path
};

// Reads a local policy file, read-only, bounded. Refuses: a path whose drive is not local (checked
// BEFORE opening, so a mapped network drive is never contacted), anything that is not a regular disk
// file (directory, console, pipe, NUL), a reparse point / offline / cloud-placeholder file (opened as
// itself, never followed or hydrated), a final path that is not a local drive letter, a file larger
// than kMaxPolicyBytes (checked before and during the read), and a path that is not valid UTF-8.
// No write, no execution. Not covered: a drive type misreported by a third-party driver.
PolicyFileRead read_policy_file(const std::string& utf8_path);

}  // namespace metasec::win
