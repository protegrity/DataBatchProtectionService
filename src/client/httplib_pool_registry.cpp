// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "httplib_pool_registry.h"

// Meyer's singleton
// This is thread-safe since C++11 (we use C++17)
// https://laristra.github.io/flecsi/src/developer-guide/patterns/meyers_singleton.html
// https://stackoverflow.com/questions/17712001/how-is-meyers-implementation-of-a-singleton-actually-a-singleton
HttplibPoolRegistry& HttplibPoolRegistry::Instance() {
    static HttplibPoolRegistry instance;
    return instance;
}

void HttplibPoolRegistry::SetPoolConfig(const std::string& base_url, const PoolConfig& config) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    auto& pool = url_to_pool_[base_url];
    pool.config = config;
}

HttplibPoolRegistry::PoolState& HttplibPoolRegistry::GetOrCreatePool(
        const std::string& base_url) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    auto it = url_to_pool_.find(base_url);

    // we did not find a pool for this base_url, so we create a new one
    if (it == url_to_pool_.end()) {
        // Construct the PoolState in-place to avoid copying/moving non-copyable members.
        auto inserted = url_to_pool_.try_emplace(base_url);
        it = inserted.first;
        // Default config
        it->second.config.max_pool_size = kDefaultMaxPoolSize;
        it->second.config.borrow_timeout = kDefaultBorrowTimeout_ms;
        it->second.config.max_idle_time = kDefaultMaxIdleTime_ms;
        it->second.config.connect_timeout = kDefaultConnectTimeout_s;
        it->second.config.read_timeout = kDefaultReadTimeout_s;
        it->second.config.write_timeout = kDefaultWriteTimeout_s;
    }
    return it->second;
}

std::unique_ptr<httplib::Client> HttplibPoolRegistry::CreateClient(const std::string& base_url, const PoolConfig& cfg) const {
    std::unique_ptr<httplib::Client> client(new httplib::Client(base_url));
    client->set_connection_timeout(static_cast<int>(cfg.connect_timeout.count()));
    client->set_read_timeout(static_cast<int>(cfg.read_timeout.count()));
    client->set_write_timeout(static_cast<int>(cfg.write_timeout.count()));
    client->set_keep_alive(true);
    return client;
}

std::unique_ptr<httplib::Client> HttplibPoolRegistry::Borrow(const std::string& base_url) {
    PoolState& pool = GetOrCreatePool(base_url);

    const auto deadline = std::chrono::steady_clock::now() + pool.config.borrow_timeout;
    std::unique_lock<std::mutex> lock(pool.mutex);

    // first iterate through the idle list and prune any clients that have been idle for too long
    // then check if there are any clients in the idle list that can be returned
    // if there are no clients in the idle list, create a new client
    // if no new client can be created, wait (via cv.wait_until()) 
    // for a client to be returned to the pool or for the borrow timeout to expire
    while (true) {
        // Prune idle
        const auto now = std::chrono::steady_clock::now();
        while (!pool.idle.empty()) {
            const auto& entry = pool.idle.front();
            if (now - entry.last_used > pool.config.max_idle_time) {
                pool.idle.pop_front();
                if (pool.total_clients > 0) {
                    pool.total_clients = pool.total_clients - 1;
                }
            } else {
                break;
            }
        }

        if (!pool.idle.empty()) {
            auto entry = std::move(pool.idle.front());
            pool.idle.pop_front();
            return std::move(entry.client);
        }

        if (pool.total_clients < pool.config.max_pool_size) {
            ++pool.total_clients;
            lock.unlock();
            auto client = CreateClient(base_url, pool.config);
            lock.lock();
            return client;
        }

        // if we get here, we have no clients in the idle list and no capacity to create a new client
        // so we wait for a client to be returned to the pool or for the borrow timeout to expire
        
        // the mutex can be unlocked here either when a client is returned to the pool
        // (via the Return() function) or when we timed out.
        // if we time out and, return a null pointer
        if (pool.cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            return std::unique_ptr<httplib::Client>();
        }
    }
}

void HttplibPoolRegistry::Return(const std::string& base_url, std::unique_ptr<httplib::Client> client) {
    PoolState& pool = GetOrCreatePool(base_url);
    std::lock_guard<std::mutex> lock(pool.mutex);
    pool.idle.push_back(PooledEntry{ std::move(client), std::chrono::steady_clock::now() });
    pool.cv.notify_one();
}

void HttplibPoolRegistry::Discard(const std::string& base_url, std::unique_ptr<httplib::Client> client) {
    // Take ownership of the client by value so callers cannot reuse it after discarding.
    // We intentionally do not return it to the idle list; destruction of the unique_ptr
    // at the end of this function will close the underlying connection.
    
    // No explicit close is required here: when this function returns and 'client' goes out
    // of scope, its destructor (via std::unique_ptr) will invoke the httplib::Client
    // destructor, which closes the underlying socket.
    (void)client; // Currently unused; kept for potential future diagnostics/cleanup.
    PoolState& pool = GetOrCreatePool(base_url);
    std::lock_guard<std::mutex> lock(pool.mutex);
    // Adjust the total number of tracked clients since one is being discarded.
    if (pool.total_clients > 0) {
        pool.total_clients = pool.total_clients - 1;
    }
    // Wake one waiter so it can attempt to borrow/create now that capacity freed.
    pool.cv.notify_one();
}


