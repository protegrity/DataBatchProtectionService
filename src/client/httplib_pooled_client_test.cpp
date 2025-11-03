#include <gtest/gtest.h>
#include <chrono>
#include <atomic>
#include <future>
#include <string>
#include <thread>
#include <httplib.h>
#include "httplib_pooled_client.h"
#include "httplib_pool_registry.h"

TEST(HttplibPooledClientTest, AcquireSingletonPerBaseUrl) {
    auto a = HttplibPooledClient::Acquire("http://127.0.0.1:18080", 2);
    auto b = HttplibPooledClient::Acquire("http://127.0.0.1:18080", 2);
    EXPECT_EQ(a.get(), b.get());
}

TEST(HttplibPooledClientTest, DifferentBaseUrlsYieldDifferentInstances) {
    auto a = HttplibPooledClient::Acquire("http://127.0.0.1:18080", 2);
    auto b = HttplibPooledClient::Acquire("http://127.0.0.1:18081", 2);
    EXPECT_NE(a.get(), b.get());
}

TEST(HttplibPooledClientTest, BasicPostEcho) {
    httplib::Server svr;
    svr.Post("/echo", [](const httplib::Request& req, httplib::Response& res) {
        res.set_content(req.body, "application/json");
    });

    //this is a test. use a random port.
    int port = svr.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread t([&]{ svr.listen_after_bind(); });

    std::string base = std::string("http://127.0.0.1:") + std::to_string(port);

    // Configure short timeouts for tests
    HttplibPoolRegistry::PoolConfig cfg;
    cfg.max_pool_size = 4;
    cfg.borrow_timeout = std::chrono::milliseconds(100);
    cfg.max_idle_time = std::chrono::milliseconds(1000);
    cfg.connect_timeout = std::chrono::seconds(1);
    cfg.read_timeout = std::chrono::seconds(1);
    cfg.write_timeout = std::chrono::seconds(1);
    HttplibPoolRegistry::Instance().SetPoolConfig(base, cfg);

    auto client = HttplibPooledClient::Acquire(base, 2);
    auto resp = client->Post("/echo", "{\"ok\":true}");
    EXPECT_GE(resp.status_code, 200);
    EXPECT_LT(resp.status_code, 300);
    EXPECT_EQ(resp.result, "{\"ok\":true}");

    svr.stop();
    t.join();
}

TEST(HttplibPooledClientTest, RetryOnFirstTransportFailure) {
    // Prepare server but delay listen to force the first client attempt to fail fast.
    httplib::Server svr;
    svr.Post("/echo", [](const httplib::Request& req, httplib::Response& res) {
        res.set_content(req.body, "application/json");
    });

    //this is a test. use a random port.
    int port = svr.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::string base = std::string("http://127.0.0.1:") + std::to_string(port);

    // Configure short connect timeout so the first attempt fails quickly while not listening.
    HttplibPoolRegistry::PoolConfig cfg;
    cfg.max_pool_size = 2;
    cfg.borrow_timeout = std::chrono::milliseconds(200);
    cfg.max_idle_time = std::chrono::milliseconds(1000);
    cfg.connect_timeout = std::chrono::seconds(0); // 0 means no timeout in some libs; ensure >=1
    cfg.connect_timeout = std::chrono::seconds(1);
    cfg.read_timeout = std::chrono::seconds(1);
    cfg.write_timeout = std::chrono::seconds(1);
    HttplibPoolRegistry::Instance().SetPoolConfig(base, cfg);

    auto client = HttplibPooledClient::Acquire(base, 2);

    // Start listening shortly after to allow retry to succeed.
    std::thread server_thread([&]{
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        svr.listen_after_bind();
    });

    auto start = std::chrono::steady_clock::now();
    auto resp = client->Post("/echo", "{\"ok\":true}");
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    EXPECT_GE(resp.status_code, 200);
    EXPECT_LT(resp.status_code, 300);
    EXPECT_EQ(resp.result, "{\"ok\":true}");
    // Should complete reasonably quickly (< ~2s given short timeouts)
    EXPECT_LT(elapsed_ms, 2000);

    svr.stop();
    server_thread.join();
}

TEST(HttplibPooledClientTest, ConcurrencyAndThroughput) {
    // Server that tracks max concurrent requests.
    std::atomic<int> in_flight(0);
    std::atomic<int> max_concurrent(0);
    httplib::Server svr;
    svr.new_task_queue = [] { return new httplib::ThreadPool(8); };
    svr.Post("/work", [&](const httplib::Request& req, httplib::Response& res) {
        int now = ++in_flight;
        while (true) {
            int prev = max_concurrent.load();
            if (now > prev) { if (max_concurrent.compare_exchange_weak(prev, now)) break; }
            else break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        --in_flight;
        res.set_content(req.body, "application/json");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread t([&]{ svr.listen_after_bind(); });

    std::string base = std::string("http://127.0.0.1:") + std::to_string(port);
    HttplibPoolRegistry::PoolConfig cfg;
    cfg.max_pool_size = 8;
    cfg.borrow_timeout = std::chrono::milliseconds(200);
    cfg.max_idle_time = std::chrono::milliseconds(1000);
    cfg.connect_timeout = std::chrono::seconds(1);
    cfg.read_timeout = std::chrono::seconds(1);
    cfg.write_timeout = std::chrono::seconds(1);
    HttplibPoolRegistry::Instance().SetPoolConfig(base, cfg);

    auto client = HttplibPooledClient::Acquire(base, 4);

    const int N = 24;
    std::vector<std::future<HttpClientInterface::HttpResponse> > futures;
    futures.reserve(N);
    for (int i = 0; i < N; ++i) {
        futures.emplace_back(std::async(std::launch::async, [client]{
            return client->Post("/work", "{\"n\":1}");
        }));
    }
    int ok = 0;
    for (auto& f : futures) {
        auto r = f.get();
        if (r.status_code >= 200 && r.status_code < 300) ++ok;
    }
    EXPECT_EQ(ok, N);
    // Expect some parallelism observed at server
    EXPECT_GE(max_concurrent.load(), 2);

    svr.stop();
    t.join();
}


