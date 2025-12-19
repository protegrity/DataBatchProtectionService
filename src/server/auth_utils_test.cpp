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
#include <chrono>
#include <map>
#include <string>

static void ExpectExpiresAtInFuture(const TokenResponse& response) {
    ASSERT_TRUE(response.expires_at_.has_value());
    const auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    EXPECT_GT(response.expires_at_.value(), now_seconds);
}

// Test ClientCredentialStore initialization with map
TEST(AuthUtilsTest, InitWithMap) {
    ClientCredentialStore store("test-secret-key");
    std::map<std::string, std::string> credentials = {
        {"client1", "key1"},
        {"client2", "key2"}
    };
    
    store.init(credentials);
    
    // Test ProcessTokenRequest with valid credentials
    std::string valid_json1 = R"({"client_id": "client1", "api_key": "key1"})";
    auto response1 = store.ProcessTokenRequest(valid_json1);
    EXPECT_TRUE(response1.token_.has_value());
    EXPECT_FALSE(response1.token_.value().empty());
    EXPECT_TRUE(response1.expires_at_.has_value());
    ExpectExpiresAtInFuture(response1);
    EXPECT_TRUE(response1.IsValid());
    
    std::string valid_json2 = R"({"client_id": "client2", "api_key": "key2"})";
    auto response2 = store.ProcessTokenRequest(valid_json2);
    EXPECT_TRUE(response2.token_.has_value());
    EXPECT_FALSE(response2.token_.value().empty());
    EXPECT_TRUE(response2.expires_at_.has_value());
    ExpectExpiresAtInFuture(response2);
    EXPECT_TRUE(response2.IsValid());
    
    // Test ProcessTokenRequest with invalid credentials
    std::string invalid_json1 = R"({"client_id": "client1", "api_key": "wrong_key"})";
    auto response3 = store.ProcessTokenRequest(invalid_json1);
    EXPECT_FALSE(response3.token_.has_value());
    EXPECT_FALSE(response3.expires_at_.has_value());
    EXPECT_EQ(response3.error_status_code_, 401);
    EXPECT_FALSE(response3.IsValid());
    EXPECT_TRUE(response3.GetValidationError().find("Invalid credentials") != std::string::npos);
    
    std::string invalid_json2 = R"({"client_id": "nonexistent", "api_key": "key1"})";
    auto response4 = store.ProcessTokenRequest(invalid_json2);
    EXPECT_FALSE(response4.token_.has_value());
    EXPECT_FALSE(response4.expires_at_.has_value());
    EXPECT_EQ(response4.error_status_code_, 401);
    EXPECT_FALSE(response4.IsValid());
    EXPECT_TRUE(response4.GetValidationError().find("Invalid credentials") != std::string::npos);
}

// Test ProcessTokenRequest parsing and validation
TEST(AuthUtilsTest, ProcessTokenRequestParsing) {
    ClientCredentialStore store("test-secret-key");
    std::map<std::string, std::string> credentials = {{"test_client", "test_key"}};
    store.init(credentials);
    
    // Valid request
    std::string valid_json = R"({"client_id": "test_client", "api_key": "test_key"})";
    auto response = store.ProcessTokenRequest(valid_json);
    EXPECT_TRUE(response.token_.has_value());
    EXPECT_TRUE(response.expires_at_.has_value());
    ExpectExpiresAtInFuture(response);
    EXPECT_TRUE(response.IsValid());
    
    // Missing client_id
    std::string missing_client_id = R"({"api_key": "test_key"})";
    response = store.ProcessTokenRequest(missing_client_id);
    EXPECT_FALSE(response.token_.has_value());
    EXPECT_FALSE(response.expires_at_.has_value());
    EXPECT_EQ(response.error_status_code_, 400);
    EXPECT_FALSE(response.IsValid());
    EXPECT_FALSE(response.GetValidationError().empty());
    
    // Missing api_key
    std::string missing_api_key = R"({"client_id": "test_client"})";
    response = store.ProcessTokenRequest(missing_api_key);
    EXPECT_FALSE(response.token_.has_value());
    EXPECT_FALSE(response.expires_at_.has_value());
    EXPECT_EQ(response.error_status_code_, 400);
    EXPECT_FALSE(response.IsValid());
    EXPECT_FALSE(response.GetValidationError().empty());
    
    // Invalid JSON
    std::string invalid_json = "{invalid json}";
    response = store.ProcessTokenRequest(invalid_json);
    EXPECT_FALSE(response.token_.has_value());
    EXPECT_FALSE(response.expires_at_.has_value());
    EXPECT_EQ(response.error_status_code_, 400);
    EXPECT_FALSE(response.IsValid());
}

// Test ProcessTokenRequest with empty client_id
TEST(AuthUtilsTest, ProcessTokenRequestEmptyClientId) {
    ClientCredentialStore store("test-secret-key");
    std::map<std::string, std::string> credentials = {{"client1", "key1"}};
    store.init(credentials);
    
    std::string empty_client_id_json = R"({"client_id": "", "api_key": "key1"})";
    auto response = store.ProcessTokenRequest(empty_client_id_json);
    EXPECT_FALSE(response.token_.has_value());
    EXPECT_FALSE(response.expires_at_.has_value());
    EXPECT_EQ(response.error_status_code_, 400);
    EXPECT_FALSE(response.IsValid());
}

// Test init with enable_credential_check flag
TEST(AuthUtilsTest, InitWithEnableCredentialCheck) {
    ClientCredentialStore store("test-secret-key");
    std::map<std::string, std::string> credentials = {{"client1", "key1"}};
    
    // Initialize with credentials first
    store.init(credentials);
    
    // Test with enable_credential_check = false (skip checking)
    store.init(false);
    
    // Should succeed even with wrong api_key when skipping credential check
    std::string wrong_key_json = R"({"client_id": "client1", "api_key": "wrong_key"})";
    auto response1 = store.ProcessTokenRequest(wrong_key_json);
    EXPECT_TRUE(response1.token_.has_value());
    EXPECT_FALSE(response1.token_.value().empty());
    EXPECT_TRUE(response1.expires_at_.has_value());
    ExpectExpiresAtInFuture(response1);
    EXPECT_TRUE(response1.IsValid());
    
    // Should succeed even with nonexistent client_id when skipping credential check
    std::string nonexistent_json = R"({"client_id": "nonexistent", "api_key": "any_key"})";
    auto response2 = store.ProcessTokenRequest(nonexistent_json);
    EXPECT_TRUE(response2.token_.has_value());
    EXPECT_FALSE(response2.token_.value().empty());
    EXPECT_TRUE(response2.expires_at_.has_value());
    ExpectExpiresAtInFuture(response2);
    EXPECT_TRUE(response2.IsValid());
    
    // Test with enable_credential_check = true (enable checking)
    store.init(true);
    
    // Should fail with wrong api_key when checking credentials
    auto response3 = store.ProcessTokenRequest(wrong_key_json);
    EXPECT_FALSE(response3.token_.has_value());
    EXPECT_FALSE(response3.expires_at_.has_value());
    EXPECT_EQ(response3.error_status_code_, 401);
    EXPECT_FALSE(response3.IsValid());
    
    // Should succeed with correct credentials
    std::string correct_json = R"({"client_id": "client1", "api_key": "key1"})";
    auto response4 = store.ProcessTokenRequest(correct_json);
    EXPECT_TRUE(response4.token_.has_value());
    EXPECT_FALSE(response4.token_.value().empty());
    EXPECT_TRUE(response4.expires_at_.has_value());
    ExpectExpiresAtInFuture(response4);
    EXPECT_TRUE(response4.IsValid());
}

// Test VerifyTokenForEndpoint with enable_credential_check = false
TEST(AuthUtilsTest, VerifyTokenForEndpointSkipCheck) {
    ClientCredentialStore store("test-secret-key");
    store.init(false);  // Disable credential checking
    
    // Should succeed (return nullopt) regardless of header when skipping check
    auto result1 = store.VerifyTokenForEndpoint("");
    EXPECT_FALSE(result1.has_value());
    
    auto result2 = store.VerifyTokenForEndpoint("Invalid header");
    EXPECT_FALSE(result2.has_value());
    
    auto result3 = store.VerifyTokenForEndpoint("Bearer invalid_token");
    EXPECT_FALSE(result3.has_value());
}

// Test VerifyTokenForEndpoint with enable_credential_check = true
TEST(AuthUtilsTest, VerifyTokenForEndpointWithCheck) {
    ClientCredentialStore store("test-secret-key");
    std::map<std::string, std::string> credentials = {{"clientAAAA", "keyAAAA"}};
    store.init(credentials);  // This sets enable_credential_check_ to true
    
    // Test with missing/empty Authorization header
    auto result1 = store.VerifyTokenForEndpoint("");
    EXPECT_TRUE(result1.has_value());
    EXPECT_TRUE(result1.value().find("Unauthorized") != std::string::npos);
    
    // Test with invalid Bearer format (no "Bearer " prefix)
    auto result2 = store.VerifyTokenForEndpoint("invalid_token");
    EXPECT_TRUE(result2.has_value());
    EXPECT_TRUE(result2.value().find("Unauthorized") != std::string::npos);
    
    // Test with invalid JWT token
    auto result3 = store.VerifyTokenForEndpoint("Bearer invalid.jwt.token");
    EXPECT_TRUE(result3.has_value());
    EXPECT_TRUE(result3.value().find("Unauthorized") != std::string::npos);
    
    // Test with valid JWT token
    std::string valid_token_json = R"({"client_id": "clientAAAA", "api_key": "keyAAAA"})";
    auto token_response = store.ProcessTokenRequest(valid_token_json);
    ASSERT_TRUE(token_response.token_.has_value());
    
    std::string bearer_token = "Bearer " + token_response.token_.value();
    auto result4 = store.VerifyTokenForEndpoint(bearer_token);
    EXPECT_FALSE(result4.has_value());  // Should succeed (return nullopt)
    
    // Test with valid JWT token but wrong format (missing space after Bearer)
    std::string invalid_bearer = "Bearer" + token_response.token_.value();
    auto result5 = store.VerifyTokenForEndpoint(invalid_bearer);
    EXPECT_TRUE(result5.has_value());
    EXPECT_TRUE(result5.value().find("Unauthorized") != std::string::npos);
}
