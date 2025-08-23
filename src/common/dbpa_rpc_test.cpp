#include "dbpa_rpc.h"
#include "../client/dbps_api_client.h"
#include "../client/httplib_client.h"
#include <iostream>
#include <memory>
#include <cassert>

using namespace dbps::external;

// Test class that inherits from RemoteDataBatchProtectionAgent to access protected members
class TestableRemoteDataBatchProtectionAgent : public RemoteDataBatchProtectionAgent {
public:
    // Constructor that takes HTTP client
    TestableRemoteDataBatchProtectionAgent(std::unique_ptr<HttpClientInterface> http_client) 
        : RemoteDataBatchProtectionAgent(std::move(http_client)) {}
    
    // Expose protected members for testing
    const std::string& get_column_name() const { return column_name_; }
    const std::string& get_column_key_id() const { return column_key_id_; }
    Type::type get_data_type() const { return data_type_; }
    CompressionCodec::type get_compression_type() const { return compression_type_; }
    const std::map<std::string, std::string>& get_connection_config() const { return connection_config_; }
    const std::string& get_app_context() const { return app_context_; }
    
    // Expose private members for testing
    const std::string& get_server_url() const { return server_url_; }
    const std::string& get_user_id() const { return user_id_; }
    const std::optional<std::string>& get_initialized() const { return initialized_; }
};

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
        int status_code;
        std::string result;
        std::string error_message;
        
        MockResponse(int code, const std::string& res, const std::string& err) 
            : status_code(code), result(res), error_message(err) {}
    };
    
    std::optional<MockResponse> health_response;
    std::optional<MockResponse> encrypt_response;
    std::optional<MockResponse> decrypt_response;
    
    HttpResponse Get(const std::string& endpoint) override {
        if (endpoint == "/healthz") {
            if (!health_response.has_value()) {
                return {500, "", "Wrong test setup: Mock health response not configured"};
            }
            return {health_response->status_code, health_response->result, health_response->error_message};
        }
        return {404, "", "Endpoint not found"};
    }
    
    HttpResponse Post(const std::string& endpoint, const std::string& json_body) override {
        if (endpoint == "/encrypt") {
            if (!encrypt_response.has_value()) {
                return {500, "", "Wrong test setup: Mock encrypt response not configured"};
            }
            return {encrypt_response->status_code, encrypt_response->result, encrypt_response->error_message};
        } else if (endpoint == "/decrypt") {
            if (!decrypt_response.has_value()) {
                return {500, "", "Wrong test setup: Mock decrypt response not configured"};
            }
            return {decrypt_response->status_code, decrypt_response->result, decrypt_response->error_message};
        }
        return {404, "", "Endpoint not found"};
    }
};

// Test basic initialization with valid configuration
bool TestBasicInitialization() {
    auto mock_client = std::make_unique<MockHttpClient>();
    mock_client->health_response = MockHttpClient::MockResponse(200, "OK", "");
    
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    agent.init("test_column", connection_config, app_context, "test_key", Type::BYTE_ARRAY, CompressionCodec::UNCOMPRESSED);
    
    // Test that initialization variables are properly set
    TEST_ASSERT(agent.get_column_name() == "test_column", "Column name should be set correctly");
    TEST_ASSERT(agent.get_column_key_id() == "test_key", "Column key ID should be set correctly");
    TEST_ASSERT(agent.get_data_type() == Type::BYTE_ARRAY, "Data type should be set correctly");
    TEST_ASSERT(agent.get_compression_type() == CompressionCodec::UNCOMPRESSED, "Compression type should be set correctly");
    
    // Test that connection config and app context are accessible
    TEST_ASSERT(agent.get_connection_config().find("server_url") != agent.get_connection_config().end(), "Connection config should contain server_url");
    TEST_ASSERT(agent.get_connection_config().at("server_url") == "http://localhost:8080", "Server URL should be set correctly");
    
    TEST_ASSERT(agent.get_app_context() == app_context, "App context should be set correctly");
    
    // Test that RemoteDataBatchProtectionAgent specific variables are set
    TEST_ASSERT(agent.get_server_url() == "http://localhost:8080", "Server URL should be extracted and set correctly");
    TEST_ASSERT(agent.get_user_id() == "test_user", "User ID should be extracted from app_context and set correctly");
    TEST_ASSERT(agent.get_initialized() == "", "Initialization should succeed with empty string (no error)");
        
    TEST_PASS("Basic Initialization");
    return true;
}

// Test decryption without initialization
bool TestDecryptWithoutInit() {
    auto mock_client = std::make_unique<MockHttpClient>();
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client));
    
    // Don't call init() - leave agent uninitialized
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Decrypt(test_data);
    
    TEST_ASSERT(result != nullptr, "Decrypt result should not be null");
    TEST_ASSERT(!result->success(), "Should fail due to not being initialized");
    
    std::string error_msg = result->error_message();
    TEST_ASSERT(error_msg.find("init() was not called") != std::string::npos, 
                "Error should indicate initialization failure");
    
    TEST_PASS("Decrypt Without Init");
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
    mock_client->health_response = MockHttpClient::MockResponse(500, "", "Server error");
    
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
    mock_client->health_response = MockHttpClient::MockResponse(200, "OK", "");
    mock_client->encrypt_response = MockHttpClient::MockResponse(
        200, 
        "{\"access\":{\"user_id\":\"test_user\",\"role\":\"EmailReader\",\"access_control\":\"granted\"},\"debug\":{\"reference_id\":\"123\"},\"data_batch_encrypted\":{\"value_format\":{\"compression\":\"UNCOMPRESSED\"},\"value\":\"dGVzdF9kYXRh\"}}", 
        ""
    );
    
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
    mock_client->decrypt_response = MockHttpClient::MockResponse(
        200, 
        "{\"access\":{\"user_id\":\"test_user\",\"role\":\"EmailReader\",\"access_control\":\"granted\"},\"debug\":{\"reference_id\":\"123\"},\"data_batch\":{\"datatype\":\"BYTE_ARRAY\",\"value_format\":{\"compression\":\"UNCOMPRESSED\",\"format\":\"RAW_C_DATA\",\"encoding\":\"BASE64\"},\"value\":\"dGVzdF9kYXRh\"}}", 
        ""
    );
    
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
    all_tests_passed &= TestDecryptWithoutInit();
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
