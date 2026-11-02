#pragma once
// Test helper: a unique directory under the system temp dir, removed on destruction.
#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>

namespace test_support {

inline std::atomic<int> g_dir_counter{0};

class TempDir {
public:
    TempDir() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        dir_ = std::filesystem::temp_directory_path() /
               ("metasec-test-" + std::to_string(stamp) + "-" + std::to_string(g_dir_counter++));
        std::filesystem::create_directories(dir_);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    std::filesystem::path file(const char* name = "events.db") const { return dir_ / name; }
    const std::filesystem::path& dir() const { return dir_; }

private:
    std::filesystem::path dir_;
};

}  // namespace test_support
