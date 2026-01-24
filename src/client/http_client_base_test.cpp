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

#include <gtest/gtest.h>

#include <atomic>
#include <string>
#include <vector>

#include "http_client_base.h"

class FakeHttpClient final : public HttpClientBase {
public:
    explicit FakeHttpClient(ClientCredentials credentials)
        : HttpClientBase("mock://", std::move(credentials)) {
    }

    void SetTokenResponse(std::string token, std::string token_type, std::int64_t expires_at) {
        token_responses_.clear();
        token_responses_.push_back(
            TokenResp{std::move(token), std::move(token_type), expires_at});
    }

    void SetTokenResponses(std::vector<std::tuple<std::string, std::string, std::int64_t> > responses) {
        token_responses_.clear();
        token_responses_.reserve(responses.size());
        for (auto& t : responses) {
            token_responses_.push_back(
                TokenResp{std::move(std::get<0>(t)), std::move(std::get<1>(t)), std::get<2>(t)});
        }
    }

    std::atomic<int> get_calls{0};
    std::atomic<int> post_calls{0};
    std::atomic<int> token_calls{0};

    std::string last_get_endpoint;
    HeaderList last_get_headers;
    std::vector<HeaderList> get_headers_history;
    bool fail_first_get_with_401 = false;
    bool fail_token_fetch = false;

protected:
    HttpResponse DoGet(const std::string& endpoint, const HeaderList& headers) override {
        ++get_calls;
        last_get_endpoint = endpoint;
        last_get_headers = headers;
        get_headers_history.push_back(headers);
        if (fail_first_get_with_401) {
            fail_first_get_with_401 = false;
            return HttpResponse(401, "Unauthorized");
        }
        return HttpResponse(200, "OK");
    }

    HttpResponse DoPost(const std::string& endpoint, const std::string& json_body, const HeaderList& headers) override {
        (void)json_body;
        (void)headers;
        ++post_calls;
        if (endpoint == "/token") {
            ++token_calls;
            if (fail_token_fetch) {
                return HttpResponse(401, "", "Unauthorized");
            }
            // Use far-future expiry so the cached token is always considered valid.
            const TokenResp* tr = nullptr;
            if (!token_responses_.empty()) {
                std::size_t idx = static_cast<std::size_t>(token_calls.load() - 1);
                if (idx >= token_responses_.size()) idx = token_responses_.size() - 1;
                tr = &token_responses_[idx];
            }
            const std::string& token = tr ? tr->token : token_;
            const std::string& token_type = tr ? tr->token_type : token_type_;
            const std::int64_t expires_at = tr ? tr->expires_at : expires_at_;
            return HttpResponse(
                200,
                std::string("{\"token\":\"") + token +
                    "\",\"token_type\":\"" + token_type +
                    "\",\"expires_at\":" + std::to_string(expires_at) + "}");
        }
        return HttpResponse(404, "", "Unexpected POST endpoint: " + endpoint);
    }

private:
    struct TokenResp {
        std::string token;
        std::string token_type;
        std::int64_t expires_at;
    };

    std::vector<TokenResp> token_responses_;
    std::string token_ = "mock_jwt";
    std::string token_type_ = "Bearer";
    std::int64_t expires_at_ = 4102444800; // 2100-01-01T00:00:00Z
};

TEST(HttpClientBaseTest, AuthRequiredDefaultFetchesTokenAndAddsAuthorizationHeader) {
    FakeHttpClient client({{"client_id", "clientA"}, {"api_key", "keyA"}});
    client.SetTokenResponse("abc", "Bearer", 4102444800);

    auto r1 = client.Get("/statusz");
    ASSERT_TRUE(r1.error_message.empty());
    ASSERT_EQ(r1.status_code, 200);

    auto auth_it = client.last_get_headers.find(HttpClientBase::kAuthorizationHeader);
    ASSERT_NE(auth_it, client.last_get_headers.end());
    ASSERT_EQ(auth_it->second, "Bearer abc");

    // Second call should use cached token.
    auto r2 = client.Get("/statusz");
    ASSERT_TRUE(r2.error_message.empty());
    ASSERT_EQ(r2.status_code, 200);
    ASSERT_EQ(client.token_calls.load(), 1);
    ASSERT_EQ(client.get_calls.load(), 2);
}

TEST(HttpClientBaseTest, AuthRequiredFalseDoesNotFetchTokenOrSendAuthorizationHeader) {
    FakeHttpClient client({{"client_id", "clientA"}, {"api_key", "keyA"}});

    auto r = client.Get("/healthz", false);
    ASSERT_TRUE(r.error_message.empty());
    ASSERT_EQ(r.status_code, 200);
    ASSERT_EQ(client.token_calls.load(), 0);
    ASSERT_EQ(client.get_calls.load(), 1);
    ASSERT_EQ(client.last_get_headers.find(HttpClientBase::kAuthorizationHeader),
              client.last_get_headers.end());
}

TEST(HttpClientBaseTest, UsesTokenTypeFromTokenResponse) {
    FakeHttpClient client({{"client_id", "clientA"}, {"api_key", "keyA"}});
    client.SetTokenResponse("xyz", "JWT", 4102444800);

    auto r = client.Get("/statusz");
    ASSERT_TRUE(r.error_message.empty());

    auto auth_it = client.last_get_headers.find(HttpClientBase::kAuthorizationHeader);
    ASSERT_NE(auth_it, client.last_get_headers.end());
    ASSERT_EQ(auth_it->second, "JWT xyz");
}

TEST(HttpClientBaseTest, RetryOnceOn401FetchesNewTokenAndRetries) {
    FakeHttpClient client({{"client_id", "clientA"}, {"api_key", "keyA"}});
    client.SetTokenResponses({
        {"t1", "Bearer", 4102444800},
        {"t2", "Bearer", 4102444800},
    });
    client.fail_first_get_with_401 = true;

    auto r = client.Get("/statusz");
    ASSERT_TRUE(r.error_message.empty());
    ASSERT_EQ(r.status_code, 200);

    ASSERT_EQ(client.token_calls.load(), 2);
    ASSERT_EQ(client.get_calls.load(), 2);

    ASSERT_GE(client.get_headers_history.size(), 2u);
    auto auth1 = client.get_headers_history[0].find(HttpClientBase::kAuthorizationHeader);
    auto auth2 = client.get_headers_history[1].find(HttpClientBase::kAuthorizationHeader);
    ASSERT_NE(auth1, client.get_headers_history[0].end());
    ASSERT_NE(auth2, client.get_headers_history[1].end());
    ASSERT_EQ(auth1->second, "Bearer t1");
    ASSERT_EQ(auth2->second, "Bearer t2");
}

TEST(HttpClientBaseTest, PrefetchTokenFetchesAndCachesToken) {
    FakeHttpClient client({{"client_id", "clientA"}, {"api_key", "keyA"}});
    client.SetTokenResponse("prefetch", "Bearer", 4102444800);

    auto error = client.PrefetchToken();
    ASSERT_FALSE(error.has_value());
    ASSERT_EQ(client.token_calls.load(), 1);

    auto r = client.Get("/statusz");
    ASSERT_TRUE(r.error_message.empty());
    ASSERT_EQ(r.status_code, 200);
    ASSERT_EQ(client.token_calls.load(), 1);
}

TEST(HttpClientBaseTest, PrefetchTokenReturnsErrorOnFailure) {
    FakeHttpClient client({{"client_id", "clientA"}, {"api_key", "keyA"}});
    client.fail_token_fetch = true;

    auto error = client.PrefetchToken();
    ASSERT_TRUE(error.has_value());
    ASSERT_NE(error->find("status code: 401"), std::string::npos);
    ASSERT_EQ(client.token_calls.load(), 1);
}


