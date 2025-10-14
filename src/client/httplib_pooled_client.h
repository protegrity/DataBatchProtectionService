#pragma once

#include <condition_variable>
#include <deque>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "http_client_interface.h"

// Implemenetation of the HttpClientInterface which uses a pool of connections for a given base_url.
// This is a singleton, accessed via the Acquire() function.
class HttplibPooledClient : public HttpClientInterface {
public:
    // Factory that returns one pooled client per base_url.
    // If cfg is provided, it will be applied to the underlying pool for the base_url.
    static std::shared_ptr<HttplibPooledClient> Acquire(
        const std::string& base_url,
        std::size_t num_worker_threads = 0);

    ~HttplibPooledClient() noexcept;

    // HttpClientInterface
    HttpResponse Get(const std::string& endpoint) override;
    HttpResponse Post(const std::string& endpoint, const std::string& json_body) override;

    // disable the copy constructor
    HttplibPooledClient(const HttplibPooledClient&) = delete;
    HttplibPooledClient& operator=(const HttplibPooledClient&) = delete;

private:
    explicit HttplibPooledClient(const std::string& base_url,
                                 std::size_t num_worker_threads);

    struct RequestTask {
        enum class Kind { Get, Post };
        Kind kind;
        std::string endpoint;
        std::string json_body;
        std::promise<HttpClientInterface::HttpResponse> promise;
    };

    void WorkerLoop();

    // Queue
    std::mutex request_queue_mutex_;
    std::condition_variable request_queue_cv_;
    std::deque<std::unique_ptr<RequestTask> > request_queue_;
    bool stopping_ = false;

    // Workers
    std::vector<std::thread> worker_threads_;

    // Configuration
    const std::string base_url_;

    // Static per-base_url registry
    static std::mutex url_to_instance_mutex_;
    static std::map<std::string, std::weak_ptr<HttplibPooledClient> > url_to_instance_;
};
