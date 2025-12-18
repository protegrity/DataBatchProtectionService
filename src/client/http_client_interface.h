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

#include <string>
#include <httplib.h>

/**
 * Interface for HTTP client implementations.
 * 
 * Thread Safety: Implementations must be thread-safe for concurrent calls.
 * Multiple threads may call Get() and Post() methods simultaneously on the same instance.
 */
class HttpClientInterface {
public:
    virtual ~HttpClientInterface() = default;

    using HeaderList = httplib::Headers;

    static constexpr const char* kJsonContentType = "application/json";
    static constexpr const char* kDefaultUserAgent = "DBPSApiClient/1.0";
    
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
    
    static HeaderList DefaultJsonGetHeaders() {
        HeaderList headers;
        headers.insert({"Accept", kJsonContentType});
        headers.insert({"User-Agent", kDefaultUserAgent});
        return headers;
    }

    static HeaderList DefaultJsonPostHeaders() {
        HeaderList headers;
        headers.insert({"Content-Type", kJsonContentType});
        headers.insert({"Accept", kJsonContentType});
        headers.insert({"User-Agent", kDefaultUserAgent});
        return headers;
    }

    virtual HttpResponse Get(const std::string& endpoint) = 0;
    virtual HttpResponse Post(const std::string& endpoint, const std::string& json_body) = 0;
};
