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

#include "http_client_interface.h"
#include <httplib.h>

class HttplibClient : public HttpClientInterface {
public:
    /**
     * Constructs an HTTP client for a given base URL.
     *
     * @param base_url The base URL (e.g., "http://127.0.0.1:18080")
     * @param credentials Authentication key/value map used by HttpClientInterface to request JWTs from /token
     */
    explicit HttplibClient(
        const std::string& base_url,
        ClientCredentials credentials);
    
protected:
    /**
     * Transport implementation for an HTTP GET to the specified endpoint.
     *
     * @param endpoint The endpoint path to request (e.g., "/healthz")
     * @param headers Fully prepared headers from HttpClientInterface (may include Authorization)
     * @return HttpResponse containing status code, response body, and any error message
     *
     * @note Connections are not reused - a new connection is established for each request
     * @note Requests are not retried on failure and they are sent immediately
     */
    HttpResponse DoGet(const std::string& endpoint, const HeaderList& headers) override;

    /**
     * Transport implementation for an HTTP POST to the specified endpoint with JSON body.
     *
     * @param endpoint The endpoint path to request (e.g., "/encrypt")
     * @param json_body The JSON payload to send in the request body
     * @param headers Fully prepared headers from HttpClientInterface (may include Authorization)
     * @return HttpResponse containing status code, response body, and any error message
     *
     * @note Connections are not reused - a new connection is established for each request
     * @note Requests are not retried on failure and they are sent immediately
     */
    HttpResponse DoPost(const std::string& endpoint, const std::string& json_body, const HeaderList& headers) override;
};
