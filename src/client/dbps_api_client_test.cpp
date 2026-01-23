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

#include <iostream>
#include <string>
#include <cassert>
#include <vector>
#include <algorithm>
#include "tcb/span.hpp"
#include "dbps_api_client.h"
#include "http_client_base.h"
#include "../common/enums.h"
#include <nlohmann/json.hpp>
#include <gtest/gtest.h>

using namespace dbps::external;
using namespace dbps::enum_utils;

// TODO: Move this to a common test utility file.
// Helper function to convert string to binary data
std::vector<uint8_t> StringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

// Utility function to compare JSON strings, ignoring specified fields
bool CompareJsonStrings(const std::string& json1, const std::string& json2, const std::vector<std::string>& ignore_fields = {}) {
    try {
        auto json1_obj = nlohmann::json::parse(json1);
        auto json2_obj = nlohmann::json::parse(json2);
        
        // Remove ignored fields from both objects
        for (const auto& field : ignore_fields) {
            json1_obj.erase(field);
            json2_obj.erase(field);
        }
        
        // nlohmann::json has built-in == operator that ignores field order
        return json1_obj == json2_obj;
    } catch (const std::exception&) {
        return false;
    }
}

// Mock HTTP client for testing
class MockHttpClient : public HttpClientBase {
public:
    MockHttpClient()
        : HttpClientBase(
              "mock://",
              ClientCredentials{{"client_id", "test_client_AAAA"}, {"api_key", "test_key_AAAA"}}) {
    }

    // Mock responses for different endpoints
    void SetMockResponse(const std::string& endpoint, const HttpResponse& response) {
        mock_responses_[endpoint] = response;
    }
    
    void SetMockPostResponse(const std::string& endpoint, const std::string& expected_body, const HttpResponse& response) {
        mock_post_responses_[endpoint] = {expected_body, response};
    }
    
protected:
    HttpResponse DoGet(const std::string& endpoint, const HeaderList& headers) override {
        (void)headers;
        auto it = mock_responses_.find(endpoint);
        if (it != mock_responses_.end()) {
            return it->second;
        }
        return HttpResponse(404, "", "Mock endpoint not found: " + endpoint);
    }
    
    HttpResponse DoPost(const std::string& endpoint, const std::string& json_body, const HeaderList& headers) override {
        (void)headers;
        if (endpoint == "/token") {
            return HttpResponse(200, R"({"token":"mock_jwt","token_type":"Bearer","expires_at":1766138275})");
        }
        auto it = mock_post_responses_.find(endpoint);
        if (it != mock_post_responses_.end()) {
            if (CompareJsonStrings(it->second.first, json_body, {"debug"})) {
                return it->second.second;
            }
            // Debug: Print the actual vs expected request
            std::cout << "DEBUG: Mock body mismatch!" << std::endl;
            std::cout << "DEBUG: Expected: " << it->second.first << std::endl;
            std::cout << "DEBUG: Actual:   " << json_body << std::endl;
            return HttpResponse(400, "", "Mock body mismatch for endpoint: " + endpoint);
        }
        return HttpResponse(404, "", "Mock POST endpoint not found: " + endpoint);
    }

private:
    std::map<std::string, HttpResponse> mock_responses_;
    std::map<std::string, std::pair<std::string, HttpResponse>> mock_post_responses_;
};

// Test-specific derived class to access protected methods for testing
class TestableEncryptApiResponse : public EncryptApiResponse {
public:
    // Expose protected methods for testing
    using EncryptApiResponse::SetHttpStatusCode;
    using EncryptApiResponse::SetApiClientError;
    using EncryptApiResponse::SetJsonRequest;
    using EncryptApiResponse::SetRawResponse;
    using EncryptApiResponse::SetJsonResponse;
};

class TestableDecryptApiResponse : public DecryptApiResponse {
public:
    // Expose protected methods for testing
    using DecryptApiResponse::SetHttpStatusCode;
    using DecryptApiResponse::SetApiClientError;
    using DecryptApiResponse::SetJsonRequest;
    using DecryptApiResponse::SetRawResponse;
    using DecryptApiResponse::SetJsonResponse;
};

// Test functions for ApiResponse base class
TEST(DBPSApiClient, ApiResponseSuccessWithValidResponse) {
    TestableEncryptApiResponse response;
    
    // Set up a valid response state
    response.SetHttpStatusCode(200);
    
    // Create a valid EncryptJsonResponse
    EncryptJsonResponse json_response;
    json_response.encrypted_value_ = StringToBytes("test@example.com");
    json_response.encrypted_compression_ = CompressionCodec::UNCOMPRESSED;
    json_response.user_id_ = "test_user";
    json_response.role_ = "test_role";
    json_response.access_control_ = "test_access";
    json_response.reference_id_ = "test_ref";
    response.SetJsonResponse(json_response);
    
    // Test that Success() returns true for valid state
    ASSERT_TRUE(response.Success());
}

TEST(DBPSApiClient, ApiResponseSuccessWithInvalidHttpStatus) {
    TestableEncryptApiResponse response;
    
    // Set up response with invalid HTTP status
    response.SetHttpStatusCode(400);
    
    // Create a valid EncryptJsonResponse
    EncryptJsonResponse json_response;
    json_response.encrypted_value_ = StringToBytes("test@example.com");
    json_response.encrypted_compression_ = CompressionCodec::UNCOMPRESSED;
    json_response.user_id_ = "test_user";
    json_response.role_ = "test_role";
    json_response.access_control_ = "test_access";
    json_response.reference_id_ = "test_ref";
    response.SetJsonResponse(json_response);
    
    // Test that Success() returns false for non-2xx status
    ASSERT_FALSE(response.Success());
}

TEST(DBPSApiClient, ApiResponseSuccessWithApiClientError) {
    TestableEncryptApiResponse response;
    
    // Set up response with API client error
    response.SetHttpStatusCode(200);
    response.SetApiClientError("Test error message");
    
    // Create a valid EncryptJsonResponse
    EncryptJsonResponse json_response;
    json_response.encrypted_value_ = StringToBytes("test@example.com");
    json_response.encrypted_compression_ = CompressionCodec::UNCOMPRESSED;
    json_response.user_id_ = "test_user";
    json_response.role_ = "test_role";
    json_response.access_control_ = "test_access";
    json_response.reference_id_ = "test_ref";
    response.SetJsonResponse(json_response);
    
    // Test that Success() returns false when API client error is set
    ASSERT_FALSE(response.Success());
}

// Test functions for EncryptApiResponse
TEST(DBPSApiClient, EncryptApiResponseGetResponseCiphertextWithValidData) {
    TestableEncryptApiResponse response;
    
    // Create a valid EncryptJsonResponse with binary data
    EncryptJsonResponse json_response;
    json_response.encrypted_value_ = StringToBytes("test@example.com");
    json_response.encrypted_compression_ = CompressionCodec::UNCOMPRESSED;
    json_response.user_id_ = "test_user";
    json_response.role_ = "test_role";
    json_response.access_control_ = "test_access";
    json_response.reference_id_ = "test_ref";
    response.SetJsonResponse(json_response);
    
    // Get the decoded ciphertext
    auto ciphertext = response.GetResponseCiphertext();
    
    // Verify the span is not empty and contains the expected data
    ASSERT_TRUE(!ciphertext.empty());
    
    // Convert span back to string for verification
    std::string decoded_string(ciphertext.begin(), ciphertext.end());
    ASSERT_EQ("test@example.com", decoded_string);
}

TEST(DBPSApiClient, EncryptApiResponseGetResponseCiphertextWithNoData) {
    TestableEncryptApiResponse response;
    
    // Don't set any JSON response, so decoded_ciphertext_ should be empty
    
    // Get the decoded ciphertext - should return empty span without throwing
    auto ciphertext = response.GetResponseCiphertext();
    
    // Verify the span is empty
    ASSERT_TRUE(ciphertext.empty());
}

// Test functions for DecryptApiResponse
TEST(DBPSApiClient, DecryptApiResponseGetResponsePlaintextWithValidData) {
    TestableDecryptApiResponse response;
    
    // Create a valid DecryptJsonResponse with binary data
    DecryptJsonResponse json_response;
    json_response.decrypted_value_ = StringToBytes("test@example.com");
    json_response.datatype_ = Type::BYTE_ARRAY;
    json_response.compression_ = CompressionCodec::UNCOMPRESSED;
    json_response.encoding_ = Encoding::PLAIN;
    json_response.user_id_ = "test_user";
    json_response.role_ = "test_role";
    json_response.access_control_ = "test_access";
    json_response.reference_id_ = "test_ref";
    response.SetJsonResponse(json_response);
    
    // Get the decoded plaintext
    auto plaintext = response.GetResponsePlaintext();
    
    // Verify the span is not empty and contains the expected data
    ASSERT_TRUE(!plaintext.empty());
    
    // Convert span back to string for verification
    std::string decoded_string(plaintext.begin(), plaintext.end());
    ASSERT_EQ("test@example.com", decoded_string);
}

TEST(DBPSApiClient, DecryptApiResponseGetResponsePlaintextWithNoData) {
    TestableDecryptApiResponse response;
    
    // Don't set any JSON response, so decoded_plaintext_ should be empty
    
    // Get the decoded plaintext - should return empty span without throwing
    auto plaintext = response.GetResponsePlaintext();
    
    // Verify the span is empty
    ASSERT_TRUE(plaintext.empty());
}

TEST(DBPSApiClient, EncryptWithValidData) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /encrypt endpoint
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "encoding": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
        "application_context": "{\"user_id\": \"test_user_456\"}",
        "debug": {"reference_id": "1755831549871"}
    })";
    
    std::string mock_response = R"({
        "data_batch_encrypted": {
            "value": "ZW5jcnlwdGVkX3Rlc3RAZXhhbXBsZS5jb20=",
            "value_format": {
                "compression": "UNCOMPRESSED"
            }
        },
        "access": {
            "user_id": "test_user",
            "role": "test_role",
            "access_control": "test_access"
        },
        "debug": {
            "reference_id": "test_ref"
        }
    })";
    
    mock_client->SetMockPostResponse("/encrypt", expected_request, 
        HttpClientBase::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::vector<uint8_t> plaintext_data = StringToBytes("test@example.com");
    
    // Call Encrypt() with valid parameters
    auto response = client.Encrypt(
        span<const uint8_t>(plaintext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        std::nullopt,               // datatype_length
        CompressionCodec::UNCOMPRESSED, // compression
        Encoding::PLAIN,         // encoding
        std::map<std::string, std::string>{}, // encoding_attributes
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456",            // user_id
        "{\"user_id\": \"test_user_456\"}" // application_context
    );
    
    // Verify the response
    if (!response.Success()) {
        std::cout << "DEBUG: Encrypt test failed with error: " << response.ErrorMessage() << std::endl;
        std::cout << "DEBUG: Error fields: " << std::endl;
        auto error_fields = response.ErrorFields();
        for (const auto& field : error_fields) {
            std::cout << "  " << field.first << ": [" << field.second << "]" << std::endl;
        }
    }
    ASSERT_TRUE(response.Success());
    
    // Get the encrypted data and verify it's not empty
    auto ciphertext = response.GetResponseCiphertext();
    ASSERT_TRUE(!ciphertext.empty());
    
    // Verify we can access the response attributes
    auto& json_response = response.GetResponseAttributes();
    ASSERT_TRUE(json_response.IsValid());
}

TEST(DBPSApiClient, DecryptWithValidData) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /decrypt endpoint
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value_format": {
                "compression": "UNCOMPRESSED",
                "encoding": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
        "application_context": "{\"user_id\": \"test_user_456\"}",
        "encryption_metadata": {},
        "debug": {"reference_id": "1755831549871"}
    })";
    
    std::string mock_response = R"({
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "encoding": "PLAIN"
            }
        },
        "access": {
            "user_id": "test_user",
            "role": "test_role",
            "access_control": "test_access"
        },
        "debug": {
            "reference_id": "test_ref"
        }
    })";
    
    mock_client->SetMockPostResponse("/decrypt", expected_request, 
        HttpClientBase::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::vector<uint8_t> ciphertext_data = StringToBytes("test@example.com");
    
    // Call Decrypt() with valid parameters
    auto response = client.Decrypt(
        span<const uint8_t>(ciphertext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        std::nullopt,               // datatype_length
        CompressionCodec::UNCOMPRESSED, // compression
        Encoding::PLAIN,         // encoding
        std::map<std::string, std::string>{}, // encoding_attributes
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456",            // user_id
        "{\"user_id\": \"test_user_456\"}", // application_context
        std::map<std::string, std::string>{} // encryption_metadata
    );
    
    // Verify the response
    if (!response.Success()) {
        std::cout << "DEBUG: Decrypt test failed with error: " << response.ErrorMessage() << std::endl;
        std::cout << "DEBUG: Error fields: " << std::endl;
        auto error_fields = response.ErrorFields();
        for (const auto& field : error_fields) {
            std::cout << "  " << field.first << ": [" << field.second << "]" << std::endl;
        }
    }
    ASSERT_TRUE(response.Success());
    
    // Get the decrypted data and verify it's not empty
    auto plaintext = response.GetResponsePlaintext();
    ASSERT_TRUE(!plaintext.empty());
    
    // Verify we can access the response attributes
    auto& json_response = response.GetResponseAttributes();
    ASSERT_TRUE(json_response.IsValid());
}

TEST(DBPSApiClient, EncryptWithInvalidData) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::vector<uint8_t> plaintext_data = StringToBytes("test@example.com");
    
    // Test empty plaintext
    std::vector<uint8_t> empty_data;
    auto response1 = client.Encrypt(
        span<const uint8_t>(empty_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        std::nullopt,               // datatype_length
        CompressionCodec::UNCOMPRESSED, // compression
        Encoding::PLAIN,         // encoding
        std::map<std::string, std::string>{}, // encoding_attributes
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456",            // user_id
        "{\"user_id\": \"test_user_456\"}" // application_context
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response1.Success());
}

TEST(DBPSApiClient, DecryptWithInvalidData) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::vector<uint8_t> ciphertext_data = StringToBytes("test@example.com");
    
    // Test empty ciphertext
    std::vector<uint8_t> empty_data;
    auto response1 = client.Decrypt(
        span<const uint8_t>(empty_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        std::nullopt,               // datatype_length
        CompressionCodec::UNCOMPRESSED, // compression
        Encoding::PLAIN,         // encoding
        std::map<std::string, std::string>{}, // encoding_attributes
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456",            // user_id
        "{\"user_id\": \"test_user_456\"}", // application_context
        std::map<std::string, std::string>{} // encryption_metadata
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response1.Success());
}

TEST(DBPSApiClient, EncryptWithInvalidJsonResponse) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /encrypt endpoint with invalid JSON
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "encoding": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
        "application_context": "{\"user_id\": \"test_user_456\"}",
        "debug": {"reference_id": "1755831549871"}
    })";
    
    // Response with valid JSON but completely different structure
    std::string mock_response = R"({
        "status": "error",
        "message": "Internal server error",
        "timestamp": "2024-01-15T10:30:00Z",
        "details": {
            "reason": "Database connection failed",
            "suggestion": "Please try again later"
        }
    })";
    
    mock_client->SetMockPostResponse("/encrypt", expected_request, 
        HttpClientBase::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::vector<uint8_t> plaintext_data = StringToBytes("test@example.com");
    
    // Call Encrypt() with valid parameters
    auto response = client.Encrypt(
        span<const uint8_t>(plaintext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        std::nullopt,               // datatype_length
        CompressionCodec::UNCOMPRESSED, // compression
        Encoding::PLAIN,         // encoding
        std::map<std::string, std::string>{}, // encoding_attributes
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456",            // user_id
        "{\"user_id\": \"test_user_456\"}" // application_context
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response.Success());
}

TEST(DBPSApiClient, DecryptWithInvalidJsonResponse) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /decrypt endpoint with invalid JSON
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value_format": {
                "compression": "UNCOMPRESSED",
                "encoding": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
        "application_context": "{\"user_id\": \"test_user_456\"}",
        "encryption_metadata": {},
        "debug": {"reference_id": "1755831549871"}
    })";
    
    // Response with valid JSON but completely different structure
    std::string mock_response = R"({
        "status": "error",
        "message": "Internal server error",
        "timestamp": "2024-01-15T10:30:00Z",
        "details": {
            "reason": "Database connection failed",
            "suggestion": "Please try again later"
        }
    })";
    
    mock_client->SetMockPostResponse("/decrypt", expected_request, 
        HttpClientBase::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::vector<uint8_t> ciphertext_data = StringToBytes("test@example.com");
    
    // Call Decrypt() with valid parameters
    auto response = client.Decrypt(
        span<const uint8_t>(ciphertext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        std::nullopt,               // datatype_length
        CompressionCodec::UNCOMPRESSED, // compression
        Encoding::PLAIN,         // encoding
        std::map<std::string, std::string>{}, // encoding_attributes
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456",            // user_id
        "{\"user_id\": \"test_user_456\"}", // application_context
        std::map<std::string, std::string>{} // encryption_metadata
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response.Success());
}

TEST(DBPSApiClient, EncryptWithEncodingAttributes) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /encrypt endpoint with encoding_attributes
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "encoding": "PLAIN",
                "encoding_attributes": {
                    "page_type": "DATA_PAGE",
                    "page_encoding": "PLAIN",
                    "data_page_num_values": "1"
                }
            }
        },
        "data_batch_encrypted": {
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
        "application_context": "{\"user_id\": \"test_user_456\"}",
        "debug": {"reference_id": "1755831549871"}
    })";
    
    std::string mock_response = R"({
        "data_batch_encrypted": {
            "value": "ZW5jcnlwdGVkX3Rlc3RAZXhhbXBsZS5jb20=",
            "value_format": {
                "compression": "UNCOMPRESSED"
            }
        },
        "access": {
            "user_id": "test_user",
            "role": "test_role",
            "access_control": "test_access"
        },
        "debug": {
            "reference_id": "test_ref"
        }
    })";
    
    mock_client->SetMockPostResponse("/encrypt", expected_request, 
        HttpClientBase::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::vector<uint8_t> plaintext_data = StringToBytes("test@example.com");
    
    // Create encoding_attributes map
    std::map<std::string, std::string> encoding_attributes;
    encoding_attributes["page_type"] = "DATA_PAGE";
    encoding_attributes["page_encoding"] = "PLAIN";
    encoding_attributes["data_page_num_values"] = "1";
    
    // Call Encrypt() with encoding_attributes
    auto response = client.Encrypt(
        span<const uint8_t>(plaintext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        std::nullopt,               // datatype_length
        CompressionCodec::UNCOMPRESSED, // compression
        Encoding::PLAIN,         // encoding
        encoding_attributes,        // encoding_attributes
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456",            // user_id
        "{\"user_id\": \"test_user_456\"}" // application_context
    );
    
    // Verify the response
    ASSERT_TRUE(response.Success());
    
    // Get the encrypted data and verify it's not empty
    auto ciphertext = response.GetResponseCiphertext();
    ASSERT_TRUE(!ciphertext.empty());
    
    // Verify we can access the response attributes
    auto& json_response = response.GetResponseAttributes();
    ASSERT_TRUE(json_response.IsValid());
}
