#include <iostream>
#include <string>
#include <cassert>
#include <vector>
#include <algorithm>
#include "../common/tcb/span.hpp"
#include "dbps_api_client.h"
#include "http_client_interface.h"
#include <nlohmann/json.hpp>

using namespace dbps::external;
using namespace dbps::enum_utils;

// Simple test framework (matching existing project style)
#define TEST(name) void test_##name()
#define ASSERT(condition) assert(condition)
#define ASSERT_EQ(expected, actual) assert((expected) == (actual))
#define ASSERT_TRUE(condition) assert(condition)
#define ASSERT_FALSE(condition) assert(!(condition))

// Test utilities
void PrintTestResult(const std::string& test_name, bool passed) {
    std::cout << (passed ? "PASS" : "FAIL") << ": " << test_name << std::endl;
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
class MockHttpClient : public HttpClientInterface {
public:
    // Mock responses for different endpoints
    void SetMockResponse(const std::string& endpoint, const HttpResponse& response) {
        mock_responses_[endpoint] = response;
    }
    
    void SetMockPostResponse(const std::string& endpoint, const std::string& expected_body, const HttpResponse& response) {
        mock_post_responses_[endpoint] = {expected_body, response};
    }
    
    // Implement the interface methods
    HttpResponse Get(const std::string& endpoint) override {
        auto it = mock_responses_.find(endpoint);
        if (it != mock_responses_.end()) {
            return it->second;
        }
        return HttpResponse(404, "", "Mock endpoint not found: " + endpoint);
    }
    
    HttpResponse Post(const std::string& endpoint, const std::string& json_body) override {
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
TEST(ApiResponseSuccessWithValidResponse) {
    TestableEncryptApiResponse response;
    
    // Set up a valid response state
    response.SetHttpStatusCode(200);
    
    // Create a valid EncryptJsonResponse
    EncryptJsonResponse json_response;
    json_response.encrypted_value_ = "dGVzdEBleGFtcGxlLmNvbQ=="; // "test@example.com" in base64
    json_response.encrypted_compression_ = "UNCOMPRESSED";
    json_response.user_id_ = "test_user";
    json_response.role_ = "test_role";
    json_response.access_control_ = "test_access";
    json_response.reference_id_ = "test_ref";
    response.SetJsonResponse(json_response);
    
    // Test that Success() returns true for valid state
    ASSERT_TRUE(response.Success());
}

TEST(ApiResponseSuccessWithInvalidHttpStatus) {
    TestableEncryptApiResponse response;
    
    // Set up response with invalid HTTP status
    response.SetHttpStatusCode(400);
    
    // Create a valid EncryptJsonResponse
    EncryptJsonResponse json_response;
    json_response.encrypted_value_ = "dGVzdEBleGFtcGxlLmNvbQ==";
    json_response.encrypted_compression_ = "UNCOMPRESSED";
    json_response.user_id_ = "test_user";
    json_response.role_ = "test_role";
    json_response.access_control_ = "test_access";
    json_response.reference_id_ = "test_ref";
    response.SetJsonResponse(json_response);
    
    // Test that Success() returns false for non-2xx status
    ASSERT_FALSE(response.Success());
}

TEST(ApiResponseSuccessWithApiClientError) {
    TestableEncryptApiResponse response;
    
    // Set up response with API client error
    response.SetHttpStatusCode(200);
    response.SetApiClientError("Test error message");
    
    // Create a valid EncryptJsonResponse
    EncryptJsonResponse json_response;
    json_response.encrypted_value_ = "dGVzdEBleGFtcGxlLmNvbQ==";
    json_response.encrypted_compression_ = "UNCOMPRESSED";
    json_response.user_id_ = "test_user";
    json_response.role_ = "test_role";
    json_response.access_control_ = "test_access";
    json_response.reference_id_ = "test_ref";
    response.SetJsonResponse(json_response);
    
    // Test that Success() returns false when API client error is set
    ASSERT_FALSE(response.Success());
}

// Test functions for EncryptApiResponse
TEST(EncryptApiResponseGetResponseCiphertextWithValidData) {
    TestableEncryptApiResponse response;
    
    // Create a valid EncryptJsonResponse with base64 encoded data
    EncryptJsonResponse json_response;
    json_response.encrypted_value_ = "dGVzdEBleGFtcGxlLmNvbQ=="; // "test@example.com" in base64
    json_response.encrypted_compression_ = "UNCOMPRESSED";
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

TEST(EncryptApiResponseGetResponseCiphertextWithNoData) {
    TestableEncryptApiResponse response;
    
    // Don't set any JSON response, so decoded_ciphertext_ should be empty
    
    // Get the decoded ciphertext - should return empty span without throwing
    auto ciphertext = response.GetResponseCiphertext();
    
    // Verify the span is empty
    ASSERT_TRUE(ciphertext.empty());
}

// Test functions for DecryptApiResponse
TEST(DecryptApiResponseGetResponsePlaintextWithValidData) {
    TestableDecryptApiResponse response;
    
    // Create a valid DecryptJsonResponse with base64 encoded data
    DecryptJsonResponse json_response;
    json_response.decrypted_value_ = "dGVzdEBleGFtcGxlLmNvbQ=="; // "test@example.com" in base64
    json_response.datatype_ = "BYTE_ARRAY";
    json_response.compression_ = "UNCOMPRESSED";
    json_response.format_ = "PLAIN";
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

TEST(DecryptApiResponseGetResponsePlaintextWithNoData) {
    TestableDecryptApiResponse response;
    
    // Don't set any JSON response, so decoded_plaintext_ should be empty
    
    // Get the decoded plaintext - should return empty span without throwing
    auto plaintext = response.GetResponsePlaintext();
    
    // Verify the span is empty
    ASSERT_TRUE(plaintext.empty());
}

TEST(EncryptWithValidData) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /encrypt endpoint
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype": "BYTE_ARRAY",
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
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
        HttpClientInterface::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::string test_plaintext = "test@example.com";
    std::vector<uint8_t> plaintext_data(test_plaintext.begin(), test_plaintext.end());
    
    // Call Encrypt() with valid parameters
    auto response = client.Encrypt(
        span<const uint8_t>(plaintext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::PLAIN,         // format
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
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

TEST(DecryptWithValidData) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /decrypt endpoint
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype": "BYTE_ARRAY",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value": "ZEdWemRFQmxlR0Z0Y0d4bExtTnZiUT09",
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
        "debug": {"reference_id": "1755831549871"}
    })";
    
    std::string mock_response = R"({
        "data_batch": {
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "datatype": "BYTE_ARRAY",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN"
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
        HttpClientInterface::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::string test_ciphertext = "dGVzdEBleGFtcGxlLmNvbQ=="; // "test@example.com" in base64
    std::vector<uint8_t> ciphertext_data(test_ciphertext.begin(), test_ciphertext.end());
    
    // Call Decrypt() with valid parameters
    auto response = client.Decrypt(
        span<const uint8_t>(ciphertext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::PLAIN,         // format
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
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

TEST(EncryptWithInvalidData) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::string test_plaintext = "test@example.com";
    std::vector<uint8_t> plaintext_data(test_plaintext.begin(), test_plaintext.end());
    
    // Test 1: Unsupported format (not PLAIN)
    auto response1 = client.Encrypt(
        span<const uint8_t>(plaintext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::RAW_BYTES,          // format - NOT PLAIN
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response1.Success());
    
    // Test 2: Empty plaintext
    std::vector<uint8_t> empty_data;
    auto response2 = client.Encrypt(
        span<const uint8_t>(empty_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::PLAIN,         // format
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response2.Success());
}

TEST(DecryptWithInvalidData) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::string test_ciphertext = "dGVzdEBleGFtcGxlLmNvbQ=="; // "test@example.com" in base64
    std::vector<uint8_t> ciphertext_data(test_ciphertext.begin(), test_ciphertext.end());
    
    // Test 1: Unsupported format (not PLAIN)
    auto response1 = client.Decrypt(
        span<const uint8_t>(ciphertext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::RAW_BYTES,          // format - NOT PLAIN
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response1.Success());
    
    // Test 2: Empty ciphertext
    std::vector<uint8_t> empty_data;
    auto response2 = client.Decrypt(
        span<const uint8_t>(empty_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::PLAIN,         // format
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response2.Success());
}

TEST(EncryptWithInvalidBase64Response) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /encrypt endpoint with invalid base64
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype": "BYTE_ARRAY",
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
        "debug": {"reference_id": "1755831549871"}
    })";
    
    // Response with valid JSON structure but invalid base64 value
    std::string mock_response = R"({
        "data_batch_encrypted": {
            "value": "INVALID_BASE64_VALUE!!!",
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
        HttpClientInterface::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::string test_plaintext = "test@example.com";
    std::vector<uint8_t> plaintext_data(test_plaintext.begin(), test_plaintext.end());
    
    // Call Encrypt() with valid parameters
    auto response = client.Encrypt(
        span<const uint8_t>(plaintext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::PLAIN,         // format
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response.Success());
}

TEST(DecryptWithInvalidBase64Response) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /decrypt endpoint with invalid base64
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype": "BYTE_ARRAY",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value": "ZEdWemRFQmxlR0Z0Y0d4bExtTnZiUT09",
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
        "debug": {"reference_id": "1755831549871"}
    })";
    
    // Response with valid JSON structure but invalid base64 value
    std::string mock_response = R"({
        "data_batch": {
            "value": "INVALID_BASE64_VALUE!!!",
            "datatype": "BYTE_ARRAY",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN"
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
        HttpClientInterface::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::string test_ciphertext = "dGVzdEBleGFtcGxlLmNvbQ=="; // "test@example.com" in base64
    std::vector<uint8_t> ciphertext_data(test_ciphertext.begin(), test_ciphertext.end());
    
    // Call Decrypt() with valid parameters
    auto response = client.Decrypt(
        span<const uint8_t>(ciphertext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::PLAIN,         // format
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response.Success());
}

TEST(EncryptWithInvalidJsonResponse) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /encrypt endpoint with invalid JSON
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype": "BYTE_ARRAY",
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
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
        HttpClientInterface::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::string test_plaintext = "test@example.com";
    std::vector<uint8_t> plaintext_data(test_plaintext.begin(), test_plaintext.end());
    
    // Call Encrypt() with valid parameters
    auto response = client.Encrypt(
        span<const uint8_t>(plaintext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::PLAIN,         // format
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response.Success());
}

TEST(DecryptWithInvalidJsonResponse) {
    // Create mock HTTP client
    auto mock_client = std::make_unique<MockHttpClient>();
    
    // Set up mock response for /decrypt endpoint with invalid JSON
    std::string expected_request = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype": "BYTE_ARRAY",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value": "ZEdWemRFQmxlR0Z0Y0d4bExtTnZiUT09",
            "value_format": {"compression": "UNCOMPRESSED"}
        },
        "encryption": {"key_id": "test_key_123"},
        "access": {"user_id": "test_user_456"},
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
        HttpClientInterface::HttpResponse(200, mock_response));
    
    // Create DBPSApiClient with mock client
    DBPSApiClient client(std::move(mock_client));
    
    // Create test data
    std::string test_ciphertext = "dGVzdEBleGFtcGxlLmNvbQ=="; // "test@example.com" in base64
    std::vector<uint8_t> ciphertext_data(test_ciphertext.begin(), test_ciphertext.end());
    
    // Call Decrypt() with valid parameters
    auto response = client.Decrypt(
        span<const uint8_t>(ciphertext_data),
        "email",                    // column_name
        Type::BYTE_ARRAY,           // datatype
        CompressionCodec::UNCOMPRESSED, // compression
        Format::PLAIN,         // format
        CompressionCodec::UNCOMPRESSED, // encrypted_compression
        "test_key_123",             // key_id
        "test_user_456"             // user_id
    );
    
    // Verify the response indicates failure
    ASSERT_FALSE(response.Success());
}

int main() {
    std::cout << "Running DBPS API Client tests..." << std::endl;
    std::cout << "==================================" << std::endl;
    
    bool all_tests_passed = true;
    
    // ApiResponse base class tests
    try {
        test_ApiResponseSuccessWithValidResponse();
        PrintTestResult("ApiResponse success with valid response", true);
    } catch (...) {
        PrintTestResult("ApiResponse success with valid response", false);
        all_tests_passed = false;
    }
    
    try {
        test_ApiResponseSuccessWithInvalidHttpStatus();
        PrintTestResult("ApiResponse success with invalid HTTP status", true);
    } catch (...) {
        PrintTestResult("ApiResponse success with invalid HTTP status", false);
        all_tests_passed = false;
    }
    
    try {
        test_ApiResponseSuccessWithApiClientError();
        PrintTestResult("ApiResponse success with API client error", true);
    } catch (...) {
        PrintTestResult("ApiResponse success with API client error", false);
        all_tests_passed = false;
    }
    
    // EncryptApiResponse tests
    try {
        test_EncryptApiResponseGetResponseCiphertextWithValidData();
        PrintTestResult("EncryptApiResponse get response ciphertext with valid data", true);
    } catch (...) {
        PrintTestResult("EncryptApiResponse get response ciphertext with valid data", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptApiResponseGetResponseCiphertextWithNoData();
        PrintTestResult("EncryptApiResponse get response ciphertext with no data", true);
    } catch (...) {
        PrintTestResult("EncryptApiResponse get response ciphertext with no data", false);
        all_tests_passed = false;
    }
    
    // DecryptApiResponse tests
    try {
        test_DecryptApiResponseGetResponsePlaintextWithValidData();
        PrintTestResult("DecryptApiResponse get response plaintext with valid data", true);
    } catch (...) {
        PrintTestResult("DecryptApiResponse get response plaintext with valid data", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptApiResponseGetResponsePlaintextWithNoData();
        PrintTestResult("DecryptApiResponse get response plaintext with no data", true);
    } catch (...) {
        PrintTestResult("DecryptApiResponse get response plaintext with no data", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptWithValidData();
        PrintTestResult("Encrypt with valid data", true);
    } catch (...) {
        PrintTestResult("Encrypt with valid data", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptWithValidData();
        PrintTestResult("Decrypt with valid data", true);
    } catch (...) {
        PrintTestResult("Decrypt with valid data", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptWithInvalidData();
        PrintTestResult("Encrypt with invalid data", true);
    } catch (...) {
        PrintTestResult("Encrypt with invalid data", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptWithInvalidData();
        PrintTestResult("Decrypt with invalid data", true);
    } catch (...) {
        PrintTestResult("Decrypt with invalid data", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptWithInvalidBase64Response();
        PrintTestResult("Encrypt with invalid base64 response", true);
    } catch (...) {
        PrintTestResult("Encrypt with invalid base64 response", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptWithInvalidBase64Response();
        PrintTestResult("Decrypt with invalid base64 response", true);
    } catch (...) {
        PrintTestResult("Decrypt with invalid base64 response", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptWithInvalidJsonResponse();
        PrintTestResult("Encrypt with invalid JSON response", true);
    } catch (...) {
        PrintTestResult("Encrypt with invalid JSON response", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptWithInvalidJsonResponse();
        PrintTestResult("Decrypt with invalid JSON response", true);
    } catch (...) {
        PrintTestResult("Decrypt with invalid JSON response", false);
        all_tests_passed = false;
    }
    
    std::cout << "==================================" << std::endl;
    if (all_tests_passed) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests failed!" << std::endl;
        return 1;
    }
}
