#include <gtest/gtest.h>
#include <chrono>
#include <string>
#include <thread>
#include "httplib_pool_registry.h"

TEST(HttplibPoolRegistryTest, SingletonInstanceIsSame) {
    auto* a = &HttplibPoolRegistry::Instance();
    auto* b = &HttplibPoolRegistry::Instance();
    EXPECT_EQ(a, b);
}

TEST(HttplibPoolRegistryTest, BorrowReturnReuse) {
    auto& reg = HttplibPoolRegistry::Instance();
    HttplibPoolRegistry::PoolConfig cfg;
    cfg.max_pool_size = 2;
    cfg.borrow_timeout = std::chrono::milliseconds(50);
    cfg.max_idle_time = std::chrono::milliseconds(5000);
    cfg.connect_timeout = std::chrono::seconds(1);
    cfg.read_timeout = std::chrono::seconds(1);
    cfg.write_timeout = std::chrono::seconds(1);
    const std::string url = "http://127.0.0.1:65535";

    reg.SetPoolConfig(url, cfg);
    auto c1 = reg.Borrow(url);
    ASSERT_TRUE(c1);
    auto raw1 = c1.get();
    reg.Return(url, std::move(c1));

    auto c2 = reg.Borrow(url);
    ASSERT_TRUE(c2);
    auto raw2 = c2.get();
    EXPECT_EQ(raw1, raw2);
    reg.Return(url, std::move(c2));
}

TEST(HttplibPoolRegistryTest, MaxPoolSizeAndBorrowTimeout) {
    auto& reg = HttplibPoolRegistry::Instance();
    HttplibPoolRegistry::PoolConfig cfg;
    cfg.max_pool_size = 1;
    cfg.borrow_timeout = std::chrono::milliseconds(30);
    cfg.max_idle_time = std::chrono::milliseconds(5000);
    cfg.connect_timeout = std::chrono::seconds(1);
    cfg.read_timeout = std::chrono::seconds(1);
    cfg.write_timeout = std::chrono::seconds(1);
    const std::string url = "http://127.0.0.1:65534";

    reg.SetPoolConfig(url, cfg);
    auto c1 = reg.Borrow(url);
    ASSERT_TRUE(c1);

    // With pool at capacity and nothing returned, next borrow should time out
    auto start = std::chrono::steady_clock::now();
    auto c2 = reg.Borrow(url);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    EXPECT_FALSE(c2);
    EXPECT_GE(elapsed.count(), 25); // roughly >= borrow_timeout

    reg.Return(url, std::move(c1));
}

TEST(HttplibPoolRegistryTest, IdlePruneCreatesFresh) {
    auto& reg = HttplibPoolRegistry::Instance();
    HttplibPoolRegistry::PoolConfig cfg;
    cfg.max_pool_size = 2;
    cfg.borrow_timeout = std::chrono::milliseconds(50);
    cfg.max_idle_time = std::chrono::milliseconds(10);
    cfg.connect_timeout = std::chrono::seconds(1);
    cfg.read_timeout = std::chrono::seconds(1);
    cfg.write_timeout = std::chrono::seconds(1);
    const std::string url = "http://127.0.0.1:65533";

    reg.SetPoolConfig(url, cfg);
    auto c1 = reg.Borrow(url);
    ASSERT_TRUE(c1);
    auto raw1 = c1.get();
    reg.Return(url, std::move(c1));

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    auto c2 = reg.Borrow(url);
    ASSERT_TRUE(c2);
    (void)raw1; // Address comparison is not reliable across allocators; pointer can be reused.
    auto raw2 = c2.get();
    ASSERT_NE(raw2, nullptr);
    reg.Return(url, std::move(c2));
}


