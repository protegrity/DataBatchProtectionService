#include "dbpa_remote.h"
#include "../client/dbps_api_client.h"
#include "../client/httplib_client.h"
#include <gtest/gtest.h>
#include <memory>
#include <vector>

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
    Type::type get_datatype() const { return datatype_; }
    CompressionCodec::type get_compression_type() const { return compression_type_; }
    const std::map<std::string, std::string>& get_connection_config() const { return connection_config_; }
    const std::string& get_app_context() const { return app_context_; }
    
    // Expose private members for testing
    const std::string& get_server_url() const { return server_url_; }
    const std::string& get_user_id() const { return user_id_; }
    const std::optional<std::string>& get_initialized() const { return initialized_; }
};

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

class RemoteDataBatchProtectionAgentTest : public ::testing::Test {
protected:
    void SetUp() override {
        mock_client_ = std::make_unique<MockHttpClient>();
    }
    
    void TearDown() override {
        mock_client_.reset();
    }
    
    std::unique_ptr<MockHttpClient> mock_client_;
};

// Test basic initialization with valid configuration
TEST_F(RemoteDataBatchProtectionAgentTest, BasicInitialization) {
    mock_client_->health_response = MockHttpClient::MockResponse(200, "OK", "");
    
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    // init() should not throw an exception for valid configuration
    EXPECT_NO_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED));
    
    // Test that initialization variables are properly set
    EXPECT_EQ(agent.get_column_name(), "test_column");
    EXPECT_EQ(agent.get_column_key_id(), "test_key");
    EXPECT_EQ(agent.get_datatype(), Type::BYTE_ARRAY);
    EXPECT_EQ(agent.get_compression_type(), CompressionCodec::UNCOMPRESSED);
    
    // Test that connection config and app context are accessible
    EXPECT_TRUE(agent.get_connection_config().find("server_url") != agent.get_connection_config().end());
    EXPECT_EQ(agent.get_connection_config().at("server_url"), "http://localhost:8080");
    EXPECT_EQ(agent.get_app_context(), app_context);
    
    // Test that RemoteDataBatchProtectionAgent specific variables are set
    EXPECT_EQ(agent.get_server_url(), "http://localhost:8080");
    EXPECT_EQ(agent.get_user_id(), "test_user");
    EXPECT_EQ(agent.get_initialized(), "");
}

// Test decryption without initialization
TEST_F(RemoteDataBatchProtectionAgentTest, DecryptWithoutInit) {
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    // Don't call init() - leave agent uninitialized
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Decrypt(test_data);
    
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(result->success());
    
    std::string error_msg = result->error_message();
    EXPECT_TRUE(error_msg.find("init() was not called") != std::string::npos);
}

// Test initialization with missing server URL
TEST_F(RemoteDataBatchProtectionAgentTest, MissingServerUrl) {
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    std::map<std::string, std::string> connection_config = {}; // No server_url
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    // init() should throw DBPSException for missing server URL
    EXPECT_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                            Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED), 
                 DBPSException);
    
    // Test that the initialized_ state reflects the failure
    EXPECT_TRUE(agent.get_initialized().has_value());
    EXPECT_FALSE(agent.get_initialized()->empty());
    EXPECT_TRUE(agent.get_initialized()->find("server_url") != std::string::npos);
    
    // Test that Encrypt() returns a failed result with the initialization error
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Encrypt(test_data);
    
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(result->success());
    
    // Check that the error message contains expected content
    std::string error_msg = result->error_message();
    EXPECT_TRUE(error_msg.find("initialized") != std::string::npos);
    EXPECT_TRUE(error_msg.find("server_url") != std::string::npos);
}

// Test initialization with missing user ID
TEST_F(RemoteDataBatchProtectionAgentTest, MissingUserId) {
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{}"; // No user_id
    
    // init() should throw DBPSException for missing user ID
    EXPECT_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                            Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED), 
                 DBPSException);
    
    // Test that the initialized_ state reflects the failure
    EXPECT_TRUE(agent.get_initialized().has_value());
    EXPECT_FALSE(agent.get_initialized()->empty());
    EXPECT_TRUE(agent.get_initialized()->find("user_id") != std::string::npos);
    
    // Test that Encrypt() returns a failed result with the initialization error
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Encrypt(test_data);
    
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(result->success());
    
    // Check that the error message contains expected content
    std::string error_msg = result->error_message();
    EXPECT_TRUE(error_msg.find("initialized") != std::string::npos);
    EXPECT_TRUE(error_msg.find("user_id") != std::string::npos);
}

// Test health check failure
TEST_F(RemoteDataBatchProtectionAgentTest, HealthCheckFailure) {
    mock_client_->health_response = MockHttpClient::MockResponse(500, "", "Server error");
    
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    // init() should throw DBPSException for health check failure
    EXPECT_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                            Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED), 
                 DBPSException);
    
    // Test that the initialized_ state reflects the failure
    EXPECT_TRUE(agent.get_initialized().has_value());
    EXPECT_FALSE(agent.get_initialized()->empty());
    EXPECT_TRUE(agent.get_initialized()->find("healthz") != std::string::npos);
    
    // Test that Encrypt() returns a failed result with the initialization error
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Encrypt(test_data);
    
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(result->success());
    
    // Check that the error message contains expected content
    std::string error_msg = result->error_message();
    EXPECT_TRUE(error_msg.find("initialized") != std::string::npos);
    EXPECT_TRUE(error_msg.find("healthz") != std::string::npos);
}

// Test successful encryption
TEST_F(RemoteDataBatchProtectionAgentTest, SuccessfulEncryption) {
    mock_client_->health_response = MockHttpClient::MockResponse(200, "OK", "");
    mock_client_->encrypt_response = MockHttpClient::MockResponse(
        200, 
        "{\"access\":{\"user_id\":\"test_user\",\"role\":\"EmailReader\",\"access_control\":\"granted\"},"
        "\"debug\":{\"reference_id\":\"123\"},"
        "\"data_batch_encrypted\":{"
        "\"value_format\":{\"compression\":\"UNCOMPRESSED\"},"
        "\"value\":\"dGVzdF9kYXRh\""
        "}}", 
        ""
    );
    
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    // init() should not throw an exception for valid configuration
    EXPECT_NO_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Encrypt(test_data);
    
    ASSERT_NE(result, nullptr);
    EXPECT_TRUE(result->success());
    EXPECT_GT(result->size(), 0);
    EXPECT_GT(result->ciphertext().size(), 0);
    EXPECT_GE(result->size(), result->ciphertext().size());
    EXPECT_NE(result->ciphertext().data(), nullptr);
    
    // Check that the encrypted data contains the expected content
    std::string ciphertext_str(reinterpret_cast<const char*>(result->ciphertext().data()), 
                              result->ciphertext().size());
    EXPECT_EQ(ciphertext_str, "test_data");
}

// Test successful decryption
TEST_F(RemoteDataBatchProtectionAgentTest, SuccessfulDecryption) {
    mock_client_->health_response = {200, "OK", ""};
    mock_client_->decrypt_response = MockHttpClient::MockResponse(
        200, 
        "{\"access\":{\"user_id\":\"test_user\",\"role\":\"EmailReader\",\"access_control\":\"granted\"},"
        "\"debug\":{\"reference_id\":\"123\"},"
        "\"data_batch\":{"
        "\"datatype\":\"BYTE_ARRAY\","
        "\"value_format\":{\"compression\":\"UNCOMPRESSED\",\"format\":\"PLAIN\"},"
        "\"value\":\"dGVzdF9kYXRh\""
        "}}", 
        ""
    );
    
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    std::map<std::string, std::string> connection_config = {{"server_url", "http://localhost:8080"}};
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    // init() should not throw an exception for valid configuration
    EXPECT_NO_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    auto result = agent.Decrypt(test_data);
    
    ASSERT_NE(result, nullptr);
    EXPECT_TRUE(result->success());
    EXPECT_GT(result->size(), 0);
    EXPECT_GT(result->plaintext().size(), 0);
    EXPECT_GE(result->size(), result->plaintext().size());
    EXPECT_NE(result->plaintext().data(), nullptr);
    
    // Check that the decrypted data contains the expected content
    std::string plaintext_str(reinterpret_cast<const char*>(result->plaintext().data()), 
                             result->plaintext().size());
    EXPECT_EQ(plaintext_str, "test_data");
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}