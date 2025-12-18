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

#include "httplib_pooled_client.h"

#include <httplib.h>
#include "httplib_pool_registry.h"

std::mutex HttplibPooledClient::url_to_instance_mutex_;
std::map<std::string, std::weak_ptr<HttplibPooledClient> > HttplibPooledClient::url_to_instance_;

std::shared_ptr<HttplibPooledClient> HttplibPooledClient::Acquire(
    const std::string& base_url,
    std::size_t num_worker_threads) {

    std::lock_guard<std::mutex> lock(url_to_instance_mutex_);

    auto it = url_to_instance_.find(base_url);
    if (it != url_to_instance_.end()) {
        // url_to_instance_ stores weak_ptr to avoid keeping instances alive unnecessarily.
        // weak_ptr::lock() attempts to promote to a shared_ptr; it returns an empty shared_ptr
        // if the instance has expired. When lock() succeeds, we can reuse the existing instance.
        // the if statement will evaluate to false if the instance has expired, 
        // and a new instance will be created in the code below.
        if (auto existing = it->second.lock()) {
            return existing;
        }
    }
    // if no value provided for num_worker_threads, default it to 2 x "hardware_concurrency" (with a min of 2 threads)
    // ("hardware_concurrency" is the reported number of threads that can be run concurrently (only a hint))
    if (num_worker_threads == 0) {
        auto hc = std::thread::hardware_concurrency();
        num_worker_threads = hc == 0 ? 2 : std::max<std::size_t>(2, hc * 2);
    }

    auto instance = std::shared_ptr<HttplibPooledClient>(
        new HttplibPooledClient(base_url, num_worker_threads));
    url_to_instance_[base_url] = instance;
    return instance;
}

HttplibPooledClient::HttplibPooledClient(const std::string& base_url,
                                         std::size_t num_worker_threads)
    : base_url_(base_url) {
        
    // reserve the space for the worker_threads_ vector
    // this is more efficient than calling emplace_back multiple times
    worker_threads_.reserve(num_worker_threads);
    for (std::size_t i = 0; i < num_worker_threads; ++i) {
        worker_threads_.emplace_back(&HttplibPooledClient::WorkerLoop, this);
    }
}

HttplibPooledClient::~HttplibPooledClient() noexcept {
    {
        std::lock_guard<std::mutex> lock(request_queue_mutex_);
        stopping_ = true;
    }
    request_queue_cv_.notify_all();
    for (auto& t : worker_threads_) {
        if (t.joinable()) t.join();
    }
    // Drain queue: set all promises with error to avoid hanging callers
    while (true) {
        std::unique_ptr<RequestTask> task;
        {
            std::lock_guard<std::mutex> lock(request_queue_mutex_);
            if (request_queue_.empty()) break;
            task = std::move(request_queue_.front());
            request_queue_.pop_front();
        }
        if (task) {
            task->promise.set_value(HttpResponse(0, "", "client shutting down"));
        }
    }
}

HttpClientInterface::HttpResponse HttplibPooledClient::Get(const std::string& endpoint) {
    std::unique_ptr<RequestTask> task(new RequestTask());
    task->kind = RequestTask::Kind::Get;
    task->endpoint = endpoint;
    std::future<HttpResponse> response_future = task->promise.get_future();
    {
        std::lock_guard<std::mutex> lock(request_queue_mutex_);
        if (stopping_) {
            return HttpResponse(0, "", "client shutting down");
        }
        request_queue_.push_back(std::move(task));
    }
    request_queue_cv_.notify_one();

    // wait for the task to complete, and return the result
    // (from the callers perspective, this is a blocking/synchronous call)
    return response_future.get();
}

HttpClientInterface::HttpResponse HttplibPooledClient::Post(const std::string& endpoint, const std::string& json_body) {
    std::unique_ptr<RequestTask> task(new RequestTask());
    task->kind = RequestTask::Kind::Post;
    task->endpoint = endpoint;
    task->json_body = json_body;
    std::future<HttpResponse> fut = task->promise.get_future();
    {
        std::lock_guard<std::mutex> lock(request_queue_mutex_);
        if (stopping_) {
            return HttpResponse(0, "", "client shutting down");
        }
        request_queue_.push_back(std::move(task));
    }
    request_queue_cv_.notify_one();

    // wait for the task to complete, and return the result
    // (from the callers perspective, this is a blocking/synchronous call)
    return fut.get();
}

// Worker thread main loop:
// - Waits for tasks on the queue (or shutdown signal).
// - Borrows a client from HttplibPoolRegistry for base_url_.
// - Executes the HTTP operation (GET/POST). On transport failure/exception,
//   discards the client and retries once with a fresh client.
// - Returns healthy clients to the pool; discards unhealthy ones.
// - On shutdown, exits when the queue is empty; remaining tasks are completed
//   with an error by the destructor after threads join.
void HttplibPooledClient::WorkerLoop() {
    auto& registry = HttplibPoolRegistry::Instance();

    while (true) {
        std::unique_ptr<RequestTask> task;
        {
            std::unique_lock<std::mutex> lock(request_queue_mutex_);
            // Wait until either a shutdown is requested or there is at least one task to process.
            // Using the predicate protects against spurious wakeups: the call returns only when
            // 'stopping_' is true or 'request_queue_' is non-empty.
            request_queue_cv_.wait(lock, [&]{ return stopping_ || !request_queue_.empty(); });
            if (stopping_ && request_queue_.empty()) return;
            task = std::move(request_queue_.front());
            request_queue_.pop_front();
        }

        // Borrow client
        // Attempts to get a connection from the per-base_url pool. If the pool cannot
        // provide a client within its configured borrow timeout, Borrow() returns null.
        // In that case, we complete the task with a timeout error and move on to the
        // next queued task.
        auto client = registry.Borrow(base_url_);
        if (!client) {
            task->promise.set_value(HttpResponse(0, "", "pool borrow timeout"));
            continue;
        }

        // Helper lambda to perform the actual HTTP operation.
        // It attempts to execute the task (GET/POST) using the borrowed client.
        // If the operation fails, it returns a failure pair with an error response.
        // If successful, it returns a success pair with the response.
        auto perform_once = [&](RequestTask& t) -> std::pair<bool, HttpResponse> {
            try {
                if (t.kind == RequestTask::Kind::Get) {
                    auto headers = HttpClientInterface::DefaultJsonGetHeaders();
                    auto res = client->Get(t.endpoint, headers);
                    if (!res) return {false, HttpResponse(0, "", "HTTP GET failed")};
                    return {true, HttpResponse(res->status, res->body)};
                } else {
                    auto headers = HttpClientInterface::DefaultJsonPostHeaders();
                    auto res = client->Post(t.endpoint, headers, t.json_body, HttpClientInterface::kJsonContentType);
                    if (!res) return {false, HttpResponse(0, "", "HTTP POST failed")};
                    return {true, HttpResponse(res->status, res->body)};
                }
            } catch (const std::exception& e) {
                return {false, HttpResponse(0, "", std::string("HTTP exception: ") + e.what())};
            }
        };

        // First attempt
        std::pair<bool, HttpResponse> attempt1 = perform_once(*task);
        if (attempt1.first) {
            registry.Return(base_url_, std::move(client));
            task->promise.set_value(attempt1.second);
            continue;
        }

        // Retry once with a fresh client
        registry.Discard(base_url_, std::move(client));
        client = registry.Borrow(base_url_);
        if (!client) {
            task->promise.set_value(HttpResponse(0, "", "pool borrow timeout after retry"));
            continue;
        }
        std::pair<bool, HttpResponse> attempt2 = perform_once(*task);
        if (attempt2.first) {
            registry.Return(base_url_, std::move(client));
            task->promise.set_value(attempt2.second);
        } else {
            registry.Discard(base_url_, std::move(client));
            task->promise.set_value(attempt2.second);
        }
    }
} //HttplibPooledClient::WorkerLoop()


