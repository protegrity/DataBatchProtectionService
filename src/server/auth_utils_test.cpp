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

#include "auth_utils.h"
#include <gtest/gtest.h>
#include <map>
#include <string>

// Test ClientCredentialStore initialization with map
TEST(AuthUtilsTest, InitWithMap) {
    ClientCredentialStore store;
    std::map<std::string, std::string> credentials = {
        {"client1", "key1"},
        {"client2", "key2"}
    };
    
    store.init(credentials);
    
    // Test GenerateJWT with valid credentials
    auto token1 = store.GenerateJWT("client1", "key1");
    EXPECT_TRUE(token1.has_value());
    EXPECT_FALSE(token1.value().empty());
    
    auto token2 = store.GenerateJWT("client2", "key2");
    EXPECT_TRUE(token2.has_value());
    EXPECT_FALSE(token2.value().empty());
    
    // Test GenerateJWT with invalid credentials
    auto token3 = store.GenerateJWT("client1", "wrong_key");
    EXPECT_FALSE(token3.has_value());
    
    auto token4 = store.GenerateJWT("nonexistent", "key1");
    EXPECT_FALSE(token4.has_value());
}

// Test ParseAuthRequest
TEST(AuthUtilsTest, ParseAuthRequest) {
    // Valid request
    std::string valid_json = R"({"client_id": "test_client", "api_key": "test_key"})";
    AuthRequest auth_req = ParseAuthRequest(valid_json);
    
    EXPECT_FALSE(auth_req.error_message.has_value());
    EXPECT_EQ(auth_req.client_id, "test_client");
    EXPECT_EQ(auth_req.api_key, "test_key");
    
    // Missing client_id
    std::string missing_client_id = R"({"api_key": "test_key"})";
    auth_req = ParseAuthRequest(missing_client_id);
    EXPECT_TRUE(auth_req.error_message.has_value());
    EXPECT_TRUE(auth_req.error_message.value().find("client_id") != std::string::npos);
    
    // Missing api_key
    std::string missing_api_key = R"({"client_id": "test_client"})";
    auth_req = ParseAuthRequest(missing_api_key);
    EXPECT_TRUE(auth_req.error_message.has_value());
    EXPECT_TRUE(auth_req.error_message.value().find("api_key") != std::string::npos);
    
    // Invalid JSON
    std::string invalid_json = "{invalid json}";
    auth_req = ParseAuthRequest(invalid_json);
    EXPECT_TRUE(auth_req.error_message.has_value());
}

// Test GenerateJWT with empty client_id
TEST(AuthUtilsTest, GenerateJWTEmptyClientId) {
    ClientCredentialStore store;
    std::map<std::string, std::string> credentials = {{"client1", "key1"}};
    store.init(credentials);
    
    auto token = store.GenerateJWT("", "key1");
    EXPECT_FALSE(token.has_value());
}

