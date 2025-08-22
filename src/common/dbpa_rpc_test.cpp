#include "dbpa_rpc.h"
#include "../client/dbps_api_client.h"
#include "../client/httplib_client.h"
#include <iostream>
#include <memory>
#include <cassert>

using namespace dbps::external;

// Test macro for simple assertions
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            std::cerr << "FAILED: " << __FUNCTION__ << " - " << message << std::endl; \
            return false; \
        } \
    } while(0)

// Test macro for checking success
#define TEST_PASS(test_name) \
    do { \
        std::cout << "PASS: " << test_name << std::endl; \
    } while(0)

// Mock HTTP client for testing
class MockHttpClient : public HttpClientInterface {
public:
    struct MockResponse {
        int status_code = 200;
        std::string result = "OK";
        std::string error_message;
    };
    
    MockResponse health_response;
    MockResponse encrypt_response;
    MockResponse decrypt_response;
    
    HttpResponse Get(const std::string& endpoint) override {
        if (endpoint == "/healthz") {
            return {health_response.status_code, health_response.result, health_response.error_message};
        }
        return {404, "", "Endpoint not found"};
    }
    
    HttpResponse Post(const std::string& endpoint, const std::string& json_body) override {
        if (endpoint == "/encrypt") {
            return {encrypt_response.status_code, encrypt_response.result, encrypt_response.error_message};
        } else if (endpoint == "/decrypt") {
            return {decrypt_response.status_code, decrypt_response.result, decrypt_response.error_message};
        }
        return {404, "", "Endpoint not found"};
    }
};

// Test basic initialization with valid configuration
bool TestBasicInitialization() {
    auto mock_client = std::make_unique<MockHttpClient>();
    mock_client->health_response = {200, "OK", ""};
    
    auto agent = RemoteDataBatchProtectionAgent(std::move(mock_client));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    agent.init("test_column", connection_config, app_context, "test_key", Type::BYTE_ARRAY, CompressionCodec::UNCOMPRESSED);
    
    // Test that initialization succeeded
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Encrypt(test_data);
    
    TEST_ASSERT(result != nullptr, "Encrypt result should not be null");
    
    // Debug: Let's see what actually happened
    std::cerr << "DEBUG: Basic initialization test - success: " << (result->success() ? "true" : "false") << std::endl;
    std::cerr << "DEBUG: Basic initialization test - error message: '" << result->error_message() << "'" << std::endl;
    
    const auto& error_fields = result->error_fields();
    std::cerr << "DEBUG: Basic initialization test - error fields:" << std::endl;
    for (const auto& field : error_fields) {
        std::cerr << "  " << field.first << ": " << field.second << std::endl;
    }
    
    TEST_ASSERT(!result->success(), "Should fail due to mock response not being set");
    
    // Check that the error fields contain the expected HTTP status code
    auto http_status_it = error_fields.find("http_status_code");
    TEST_ASSERT(http_status_it != error_fields.end(), "Error fields should contain HTTP status code");
    TEST_ASSERT(http_status_it->second == "404", "HTTP status code should be 404 for missing endpoint");
    
    TEST_PASS("Basic Initialization");
    return true;
}

// Test initialization with missing server URL
bool TestMissingServerUrl() {
    auto mock_client = std::make_unique<MockHttpClient>();
    auto agent = RemoteDataBatchProtectionAgent(std::move(mock_client));
    
    std::map<std::string, std::string> connection_config = {}; // No server_url
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    agent.init("test_column", connection_config, app_context, "test_key", Type::BYTE_ARRAY, CompressionCodec::UNCOMPRESSED);
    
    // Test that initialization failed
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Encrypt(test_data);
    
    TEST_ASSERT(result != nullptr, "Encrypt result should not be null");
    TEST_ASSERT(!result->success(), "Should fail due to missing server URL");
    
    // Check that the error message contains expected content
    std::string error_msg = result->error_message();
    std::cerr << "DEBUG: Missing server URL test - error message: '" << error_msg << "'" << std::endl;
    TEST_ASSERT(error_msg.find("initialized") != std::string::npos && 
                error_msg.find("server_url") != std::string::npos,
                "Error should indicate initialization and server URL failure");
    
    TEST_PASS("Missing Server URL");
    return true;
}

// Test initialization with missing user ID
bool TestMissingUserId() {
    auto mock_client = std::make_unique<MockHttpClient>();
    auto agent = RemoteDataBatchProtectionAgent(std::move(mock_client));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{}"; // No user_id
    
    agent.init("test_column", connection_config, app_context, "test_key", Type::BYTE_ARRAY, CompressionCodec::UNCOMPRESSED);
    
    // Test that initialization failed
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Encrypt(test_data);
    
    TEST_ASSERT(result != nullptr, "Encrypt result should not be null");
    TEST_ASSERT(!result->success(), "Should fail due to missing user ID");
    
    // Check that the error message contains expected content
    std::string error_msg = result->error_message();
    std::cerr << "DEBUG: Missing user ID test - error message: '" << error_msg << "'" << std::endl;
    TEST_ASSERT(error_msg.find("initialized") != std::string::npos && 
                error_msg.find("user_id") != std::string::npos,
                "Error should indicate initialization and user ID failure");
    
    TEST_PASS("Missing User ID");
    return true;
}

// Test health check failure
bool TestHealthCheckFailure() {
    auto mock_client = std::make_unique<MockHttpClient>();
    mock_client->health_response = {500, "", "Server error"};
    
    auto agent = RemoteDataBatchProtectionAgent(std::move(mock_client));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    agent.init("test_column", connection_config, app_context, "test_key", Type::BYTE_ARRAY, CompressionCodec::UNCOMPRESSED);
    
    // Test that initialization failed due to health check
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Encrypt(test_data);
    
    TEST_ASSERT(result != nullptr, "Encrypt result should not be null");
    TEST_ASSERT(!result->success(), "Should fail due to health check failure");
    
    // Check that the error message contains expected content
    std::string error_msg = result->error_message();
    std::cerr << "DEBUG: Health check failure test - error message: '" << error_msg << "'" << std::endl;
    TEST_ASSERT(error_msg.find("initialized") != std::string::npos && 
                error_msg.find("healthz") != std::string::npos,
                "Error should indicate initialization and health check failure");
    
    TEST_PASS("Health Check Failure");
    return true;
}

// Test successful encryption
bool TestSuccessfulEncryption() {
    auto mock_client = std::make_unique<MockHttpClient>();
    mock_client->health_response = {200, "OK", ""};
    mock_client->encrypt_response = {
        200, 
        "{\"access\":{\"user_id\":\"test_user\",\"role\":\"EmailReader\",\"access_control\":\"granted\"},\"debug\":{\"reference_id\":\"123\"},\"data_batch_encrypted\":{\"value_format\":{\"compression\":\"UNCOMPRESSED\"},\"value\":\"dGVzdF9kYXRh\"}}", 
        ""
    };
    
    auto agent = RemoteDataBatchProtectionAgent(std::move(mock_client));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    agent.init("test_column", connection_config, app_context, "test_key", Type::BYTE_ARRAY, CompressionCodec::UNCOMPRESSED);
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Encrypt(test_data);
    
    TEST_ASSERT(result != nullptr, "Encrypt result should not be null");
    if (!result->success()) {
        std::cerr << "Encryption failed with error: " << result->error_message() << std::endl;
        for (const auto& field : result->error_fields()) {
            std::cerr << "  " << field.first << ": " << field.second << std::endl;
        }
    }
    TEST_ASSERT(result->success(), "Encryption should succeed");
    TEST_ASSERT(result->size() > 0, "Encrypted data should have size > 0");
    TEST_ASSERT(result->ciphertext().size() > 0, "Encrypted data should have size > 0");
    TEST_ASSERT(result->ciphertext().data() != nullptr, "Encrypted data should have non-null data");
    
    // Check that the encrypted data contains the expected content
    std::string ciphertext_str(reinterpret_cast<const char*>(result->ciphertext().data()), result->ciphertext().size());
    TEST_ASSERT(result->ciphertext().size() > 0, "Encrypted data should have size > 0");
    TEST_ASSERT(ciphertext_str == "test_data", "Encrypted data should contain 'test_data'");
    
    TEST_PASS("Successful Encryption");
    return true;
}

// Test successful decryption
bool TestSuccessfulDecryption() {
    auto mock_client = std::make_unique<MockHttpClient>();
    mock_client->health_response = {200, "OK", ""};
    mock_client->decrypt_response = {
        200, 
        "{\"access\":{\"user_id\":\"test_user\",\"role\":\"EmailReader\",\"access_control\":\"granted\"},\"debug\":{\"reference_id\":\"123\"},\"data_batch\":{\"datatype\":\"BYTE_ARRAY\",\"value_format\":{\"compression\":\"UNCOMPRESSED\",\"format\":\"RAW_C_DATA\",\"encoding\":\"BASE64\"},\"value\":\"dGVzdF9kYXRh\"}}", 
        ""
    };
    
    auto agent = RemoteDataBatchProtectionAgent(std::move(mock_client));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    agent.init("test_column", connection_config, app_context, "test_key", Type::BYTE_ARRAY, CompressionCodec::UNCOMPRESSED);
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Decrypt(test_data);
    
    TEST_ASSERT(result != nullptr, "Decrypt result should not be null");
    if (!result->success()) {
        std::cerr << "Decryption failed with error: " << result->error_message() << std::endl;
        for (const auto& field : result->error_fields()) {
            std::cerr << "  " << field.first << ": " << field.second << std::endl;
        }
    }
    TEST_ASSERT(result->success(), "Decryption should succeed");
    TEST_ASSERT(result->size() > 0, "Decrypted data should have size > 0");
    TEST_ASSERT(result->plaintext().data() != nullptr, "Decrypted data should have non-null data");
    
    // Check that the decrypted data contains the expected content
    std::string plaintext_str(reinterpret_cast<const char*>(result->plaintext().data()), result->plaintext().size());
    TEST_ASSERT(result->plaintext().size() > 0, "Decrypted data should have size > 0");
    TEST_ASSERT(plaintext_str == "test_data", "Decrypted data should contain 'test_data'");
    
    TEST_PASS("Successful Decryption");
    return true;
}

// Main test runner
int main() {
    std::cout << "Running Remote DataBatchProtectionAgent tests..." << std::endl;
    std::cout << "=============================================" << std::endl;
    
    bool all_tests_passed = true;
    
    all_tests_passed &= TestBasicInitialization();
    all_tests_passed &= TestMissingServerUrl();
    all_tests_passed &= TestMissingUserId();
    all_tests_passed &= TestHealthCheckFailure();
    all_tests_passed &= TestSuccessfulEncryption();
    all_tests_passed &= TestSuccessfulDecryption();
    
    std::cout << "=============================================" << std::endl;
    if (all_tests_passed) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests failed!" << std::endl;
        return 1;
    }
}
