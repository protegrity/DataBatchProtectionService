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
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <httplib.h>

/**
 * Interface for HTTP client implementations.
 * 
 * Thread Safety: Implementations must be thread-safe for concurrent calls.
 * Multiple threads may call Get() and Post() methods simultaneously on the same instance.
 */
class HttpClientBase {
public:
    virtual ~HttpClientBase() = default;

    using ClientCredentials = std::map<std::string, std::string>;
    using HeaderList = httplib::Headers;

    static constexpr const char* kJsonContentType = "application/json";
    static constexpr const char* kDefaultUserAgent = "DBPSApiClient/1.0";
    static constexpr const char* kAuthorizationHeader = "Authorization";
    // Token expiry skew in seconds. Adds padding to the expiration time to refresh it before expiration.
    static inline constexpr std::int64_t kTokenExpirySkewSeconds = 30;
    
    struct HttpResponse {
        int status_code;
        std::string result;
        std::string error_message;
        
        HttpResponse() : status_code(0), result(""), error_message("") {}
        
        HttpResponse(int code, std::string response_result) 
            : status_code(code), result(std::move(response_result)), error_message("") {}
        
        HttpResponse(int code, std::string response_result, std::string error) 
            : status_code(code), result(std::move(response_result)), error_message(std::move(error)) {}
    };
    
    HttpResponse Get(const std::string& endpoint, bool auth_required = true);
    HttpResponse Post(const std::string& endpoint, const std::string& json_body, bool auth_required = true);

protected:
    explicit HttpClientBase(std::string base_url,
                                 ClientCredentials credentials = {})
        : base_url_(std::move(base_url)),
          credentials_(std::move(credentials)) {
    }

    virtual HttpResponse DoGet(const std::string& endpoint, const HeaderList& headers) = 0;
    virtual HttpResponse DoPost(const std::string& endpoint, const std::string& json_body, const HeaderList& headers) = 0;

    const std::string base_url_;
    const ClientCredentials credentials_;

private:
    // Header list helpers
    static HeaderList DefaultJsonGetHeaders();
    static HeaderList DefaultJsonPostHeaders();
    std::string AddAuthorizationHeader(HeaderList& headers);

    // Private struct to hold the token, token type, and expiration time.
    // It is intentionally separate from the server-side authentication logic to avoid server<>client coupling.
    struct TokenWithExpiration {
        std::string token;
        std::string token_type;
        std::int64_t expires_at = 0;
    };
    std::optional<TokenWithExpiration> cached_token_;
    
    // Thread-safe synchronization variables while fetching token
    std::mutex token_mutex_;
    std::condition_variable token_cv_;
    bool token_fetch_in_progress_ = false;

    // Thread-safe synchronization functions while fetching token
    std::optional<TokenWithExpiration> EnsureValidToken(std::string& error);
    std::optional<TokenWithExpiration> FetchToken(std::string& error);
    void InvalidateCachedToken();
};
