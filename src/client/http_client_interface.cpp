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

#include "http_client_interface.h"

#include <chrono>

#include "json_request.h"

HttpClientInterface::HeaderList HttpClientInterface::DefaultJsonGetHeaders() {
    HeaderList headers;
    headers.insert({"Accept", kJsonContentType});
    headers.insert({"User-Agent", kDefaultUserAgent});
    return headers;
}

HttpClientInterface::HeaderList HttpClientInterface::DefaultJsonPostHeaders() {
    HeaderList headers;
    headers.insert({"Content-Type", kJsonContentType});
    headers.insert({"Accept", kJsonContentType});
    headers.insert({"User-Agent", kDefaultUserAgent});
    return headers;
}

HttpClientInterface::HttpResponse HttpClientInterface::Get(const std::string& endpoint, bool auth_required) {
    const auto attempt = [&]() -> HttpResponse {
        auto headers = DefaultJsonGetHeaders();
        if (auth_required) {
            auto auth_error = AddAuthorizationHeader(headers);
            if (!auth_error.empty()) {
                return HttpResponse(0, "", auth_error);
            }
        }
        return DoGet(endpoint, headers);
    };

    auto result = attempt();
    if (auth_required && result.status_code == 401) {
        InvalidateCachedToken();
        result = attempt();
    }
    return result;
}

HttpClientInterface::HttpResponse HttpClientInterface::Post(const std::string& endpoint,
                                                            const std::string& json_body,
                                                            bool auth_required) {
    const auto attempt = [&]() -> HttpResponse {
        auto headers = DefaultJsonPostHeaders();
        if (auth_required) {
            auto auth_error = AddAuthorizationHeader(headers);
            if (!auth_error.empty()) {
                return HttpResponse(0, "", auth_error);
            }
        }
        return DoPost(endpoint, json_body, headers);
    };

    auto result = attempt();
    if (auth_required && result.status_code == 401) {
        InvalidateCachedToken();
        result = attempt();
    }
    return result;
}

std::string HttpClientInterface::AddAuthorizationHeader(HeaderList& headers) {
    std::string token_or_error;
    auto token_opt = EnsureValidToken(token_or_error);
    if (!token_opt.has_value()) {
        return token_or_error;
    }

    headers.erase(kAuthorizationHeader);
    std::string auth_value = token_opt->token_type;
    if (auth_value.back() != ' ') {
        auth_value.push_back(' ');
    }
    auth_value += token_opt->token;
    headers.insert({kAuthorizationHeader, auth_value});
    return "";
}

std::optional<HttpClientInterface::CachedToken> HttpClientInterface::EnsureValidToken(std::string& error) {

    const auto now_epoch_seconds = []() -> std::int64_t {
        const auto now = std::chrono::system_clock::now();
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        return static_cast<std::int64_t>(secs);
    };

    const auto is_token_valid_at = [&](std::int64_t now) -> bool {
        return cached_token_.has_value() &&
               !cached_token_->token.empty() &&
               cached_token_->expires_at > (now + kTokenExpirySkewSeconds);
    };

    error.clear();
    const auto now = now_epoch_seconds();

    {
        std::unique_lock<std::mutex> lock(token_mutex_);
        if (is_token_valid_at(now)) {
            return cached_token_;
        }
        while (token_fetch_in_progress_) {
            token_cv_.wait(lock);
            if (is_token_valid_at(now_epoch_seconds())) {
                return cached_token_;
            }
        }
        token_fetch_in_progress_ = true;
    }

    // Fetch token without holding token_mutex_.
    std::optional<CachedToken> fetched = FetchToken(error);

    {
        std::lock_guard<std::mutex> lock(token_mutex_);
        token_fetch_in_progress_ = false;
        if (fetched.has_value()) {
            cached_token_ = fetched;
        }
    }
    token_cv_.notify_all();
    return fetched;
}

std::optional<HttpClientInterface::CachedToken> HttpClientInterface::FetchToken(std::string& error) {
    error.clear();
    TokenRequest token_req;
    token_req.credential_values_ = credentials_;

    // IMPORTANT: call DoPost directly (authless) to avoid recursion.
    auto http_resp = DoPost("/token", token_req.ToJson(), DefaultJsonPostHeaders());
    if (!http_resp.error_message.empty() || http_resp.status_code != 200) {
        error = http_resp.error_message + " (status code: " + std::to_string(http_resp.status_code) + ")";
        return std::nullopt;
    }

    TokenResponse token_resp;
    token_resp.Parse(http_resp.result);
    if (!token_resp.IsValid()) {
        error = token_resp.GetValidationError();
        if (error.empty()) {
            error = "While reading token response, found an invalid token response: " + http_resp.result;
        }
        return std::nullopt;
    }
    
    CachedToken result;
    result.token = token_resp.token_.value();
    result.token_type = token_resp.token_type_.value();
    result.expires_at = token_resp.expires_at_.value();
    return result;
}

void HttpClientInterface::InvalidateCachedToken() {
    std::lock_guard<std::mutex> lock(token_mutex_);
    cached_token_ = std::nullopt;
}
