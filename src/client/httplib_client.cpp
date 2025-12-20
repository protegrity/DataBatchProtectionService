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

#include "httplib_client.h"

HttplibClient::HttplibClient(const std::string& base_url, ClientCredentials credentials)
    : HttpClientBase(base_url, std::move(credentials)) {
}

HttpClientBase::HttpResponse HttplibClient::DoGet(const std::string& endpoint, const HeaderList& headers) {
    try {
        httplib::Client client(base_url_);
        
        client.set_connection_timeout(10);
        client.set_read_timeout(30);
        
        // Make the GET request
        auto result = client.Get(endpoint, headers);
        
        if (!result) {
            return HttpResponse(0, "", "HTTP GET request failed: no response received");
        }
        
        return HttpResponse(result->status, result->body);
        
    } catch (const std::exception& e) {
        return HttpResponse(0, "", "GET request failed for endpoint " + endpoint + ": " + std::string(e.what()));
    }
}

HttpClientBase::HttpResponse HttplibClient::DoPost(const std::string& endpoint, const std::string& json_body, const HeaderList& headers) {
    try {
        httplib::Client client(base_url_);
        
        client.set_connection_timeout(10);
        client.set_read_timeout(30);
        
        // Make the POST request
        auto result = client.Post(endpoint, headers, json_body, HttpClientBase::kJsonContentType);
        
        if (!result) {
            return HttpResponse(0, "", "HTTP POST request failed: no response received");
        }
        
        return HttpResponse(result->status, result->body);
        
    } catch (const std::exception& e) {
        return HttpResponse(0, "", "HTTP POST request failed for endpoint " + endpoint + ": " + std::string(e.what()));
    }
}
