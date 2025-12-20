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
        std::size_t num_worker_threads,
        ClientCredentials credentials);

    ~HttplibPooledClient() noexcept;

    // disable the copy constructor
    HttplibPooledClient(const HttplibPooledClient&) = delete;
    HttplibPooledClient& operator=(const HttplibPooledClient&) = delete;

private:
    // private constructor
    explicit HttplibPooledClient(const std::string& base_url,
                                 std::size_t num_worker_threads,
                                 ClientCredentials credentials);

    struct RequestTask {
        enum class Kind { Get, Post };
        Kind kind;
        std::string endpoint;
        std::string json_body;
        HeaderList headers;
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

protected:
    HttpResponse DoGet(const std::string& endpoint, const HeaderList& headers) override;
    HttpResponse DoPost(const std::string& endpoint, const std::string& json_body, const HeaderList& headers) override;

    // Static per-base_url registry
    static std::mutex url_to_instance_mutex_;
    static std::map<std::string, std::weak_ptr<HttplibPooledClient> > url_to_instance_;
};
