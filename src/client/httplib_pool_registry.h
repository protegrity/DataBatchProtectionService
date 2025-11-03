#pragma once

#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include <httplib.h>

// This class registers and manages a pool of connections for specific URLS.
// It is a singleton, accessed via the Instance() function.
class HttplibPoolRegistry {
public:
    // Default configuration constants for PoolConfig
    static constexpr std::size_t kDefaultMaxPoolSize = 8;
    static constexpr std::chrono::milliseconds kDefaultBorrowTimeout_ms{100};
    static constexpr std::chrono::milliseconds kDefaultMaxIdleTime_ms{60*1000}; // 60 seconds
    static constexpr std::chrono::seconds kDefaultConnectTimeout_s{5};
    static constexpr std::chrono::seconds kDefaultReadTimeout_s{20};
    static constexpr std::chrono::seconds kDefaultWriteTimeout_s{20};

    struct PoolConfig {
        // Maximum number of live clients allowed in the pool for a base URL
        std::size_t max_pool_size;

        // Maximum time to wait to borrow a client before giving up (null returned)
        // Units: milliseconds
        std::chrono::milliseconds borrow_timeout;

        // Maximum time an idle client is kept in the pool before being pruned
        // Units: milliseconds
        std::chrono::milliseconds max_idle_time;

        // Connection timeout applied to underlying httplib::Client
        // Units: seconds
        std::chrono::seconds connect_timeout;

        // Read timeout applied to underlying httplib::Client
        // Units: seconds
        std::chrono::seconds read_timeout;

        // Write timeout applied to underlying httplib::Client
        // Units: seconds
        std::chrono::seconds write_timeout;
    };

    // Returns a singleton reference to the registry.
    // Call is thread-safe.
    static HttplibPoolRegistry& Instance();

    // Ensure pool exists for base_url and set/overwrite its configuration.
    // Can be invoked before of after the pool is created/used.
    void SetPoolConfig(const std::string& base_url, const PoolConfig& config);

    // Borrow/Return/Discard client for base_url.
    std::unique_ptr<httplib::Client> Borrow(const std::string& base_url);
    void Return(const std::string& base_url, std::unique_ptr<httplib::Client> client);
    void Discard(const std::string& base_url, std::unique_ptr<httplib::Client> client);

private:
    HttplibPoolRegistry() {}
    HttplibPoolRegistry(const HttplibPoolRegistry&); // not implemented
    HttplibPoolRegistry& operator=(const HttplibPoolRegistry&); // not implemented

    struct PooledEntry {
        std::unique_ptr<httplib::Client> client;
        std::chrono::steady_clock::time_point last_used;
    };

    struct PoolState {
        PoolConfig config;
        std::mutex mutex;
        std::condition_variable cv;
        std::deque<PooledEntry> idle;
        std::size_t total_clients = 0;
    };

    // Returns reference to PoolState for base_url, creating it if not present with default config.
    PoolState& GetOrCreatePool(const std::string& base_url);

    // Create and configure a new client for base_url.
    std::unique_ptr<httplib::Client> CreateClient(const std::string& base_url, const PoolConfig& cfg) const;

    // Map access
    std::mutex registry_mutex_;
    std::map<std::string, PoolState> url_to_pool_;
};


