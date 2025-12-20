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

#include "dbpa_remote.h"
#include "../client/dbps_api_client.h"
#include "../client/httplib_client.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <map>

using namespace dbps::external;

// Test class that inherits from RemoteDataBatchProtectionAgent to access protected members
class TestableRemoteDataBatchProtectionAgent : public RemoteDataBatchProtectionAgent {
public:
    // Default constructor - no HTTP client provided
    TestableRemoteDataBatchProtectionAgent() = default;
    
    // Constructor that takes HTTP client
    TestableRemoteDataBatchProtectionAgent(std::unique_ptr<HttpClientInterface> http_client) 
        : RemoteDataBatchProtectionAgent(std::move(http_client)) {}
    
    // Expose protected members for testing
    const std::string& get_column_name() const { return column_name_; }
    const std::string& get_column_key_id() const { return column_key_id_; }
    Type::type get_datatype() const { return datatype_; }
    CompressionCodec::type get_compression_type() const { return compression_type_; }
    const std::map<std::string, std::string>& get_configuration_map() const { return configuration_map_; }
    const std::string& get_app_context() const { return app_context_; }
    
    // Expose private members for testing
    const std::string& get_server_url() const { return server_url_; }
    const std::string& get_user_id() const { return user_id_; }
    const std::optional<std::string>& get_initialized() const { return initialized_; }
    
    // Expose connection config key for testing
    using RemoteDataBatchProtectionAgent::k_connection_config_key_;
    
    // Expose protected helper methods as public for testing
    using RemoteDataBatchProtectionAgent::ExtractPoolConfig;
    using RemoteDataBatchProtectionAgent::ExtractNumWorkerThreads;
    using RemoteDataBatchProtectionAgent::ExtractClientCredentials;
};

// Mock HTTP client for testing
class MockHttpClient : public HttpClientInterface {
public:
    MockHttpClient()
        : HttpClientInterface(
              "mock://",
              ClientCredentials{{"client_id", "test_client_AAAA"}, {"api_key", "test_key_AAAA"}}) {
    }

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
    
protected:
    HttpResponse DoGet(const std::string& endpoint, const HeaderList& headers) override {
        (void)headers;
        if (endpoint == "/healthz") {
            if (!health_response.has_value()) {
                return {500, "", "Wrong test setup: Mock health response not configured"};
            }
            return {health_response->status_code, health_response->result, health_response->error_message};
        }
        return {404, "", "Endpoint not found"};
    }
    
    HttpResponse DoPost(const std::string& endpoint, const std::string& json_body, const HeaderList& headers) override {
        (void)headers;
        (void)json_body;
        if (endpoint == "/token") {
            return HttpResponse(200, R"({"token":"mock_jwt","token_type":"Bearer","expires_at":1766138275})");
        }
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
        for (const auto& file_path : tmp_test_data_dir_) {
            if (std::filesystem::exists(file_path)) {
                std::filesystem::remove(file_path);
            }
        }
        tmp_test_data_dir_.clear();
    }

    void CreateTemporaryConnectionConfigFile(
      const std::string& file_contents, const std::string& file_name) {
        std::string tmp_file_path = std::filesystem::temp_directory_path() / file_name;

        std::ofstream file(tmp_file_path);
        if (file.is_open()) {
            file << file_contents;
            file.close();
            tmp_test_data_dir_.push_back(tmp_file_path);
        } else {
            throw std::runtime_error(
                "Failed to create temporary connection config file: " + tmp_file_path);
        }
    }

    std::map<std::string, std::string> GetConfigurationMap(
      const std::string& file_contents, const std::string& file_name) {
        std::string tmp_file_path = std::filesystem::temp_directory_path() / file_name;
        if (!std::filesystem::exists(tmp_file_path)) {
            CreateTemporaryConnectionConfigFile(file_contents, file_name);
        }
        return {{TestableRemoteDataBatchProtectionAgent::k_connection_config_key_, tmp_file_path}};
    }

    void TestConnectionConfigFailures(const std::map<std::string, std::string>& configuration_map) {
        auto agent = TestableRemoteDataBatchProtectionAgent();
        
        std::string app_context = "{\"user_id\": \"test_user\"}";
        
        // init() should throw DBPSException for missing server URL
        EXPECT_THROW(agent.init("test_column", configuration_map, app_context, "test_key", 
                                Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt), 
                     DBPSException);
        
        // Test that the initialized_ state reflects the failure
        EXPECT_TRUE(agent.get_initialized().has_value());
        EXPECT_FALSE(agent.get_initialized()->empty());
        EXPECT_TRUE(agent.get_initialized()->find("server_url") != std::string::npos);
        
        // Test that Encrypt() returns a failed result with the initialization error
        std::vector<uint8_t> test_data = {1, 2, 3, 4};
        std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}};
        auto result = agent.Encrypt(test_data, encoding_attributes);
        
        ASSERT_NE(result, nullptr);
        EXPECT_FALSE(result->success());
        
        // Check that the error message contains expected content
        std::string error_msg = result->error_message();
        EXPECT_TRUE(error_msg.find("initialized") != std::string::npos);
        EXPECT_TRUE(error_msg.find("server_url") != std::string::npos);
    }
    
    std::unique_ptr<MockHttpClient> mock_client_;
    std::vector<std::string> tmp_test_data_dir_;
};

TEST(RemoteDataBatchProtectionAgentCredentialsTest, ExtractCredentialsEmptyWhenNoPrefixedKeys) {
    TestableRemoteDataBatchProtectionAgent agent;
    auto cfg = nlohmann::json::parse(R"({"server_url":"http://localhost:8080"})");
    auto creds = agent.ExtractClientCredentials(cfg);
    EXPECT_TRUE(creds.empty());
}

TEST(RemoteDataBatchProtectionAgentCredentialsTest, ExtractCredentialsStripsPrefix) {
    TestableRemoteDataBatchProtectionAgent agent;
    auto cfg = nlohmann::json::parse(
        R"({"credentials.client_id":"client1","credentials.api_key":"key1","credentials.extra":"v","not_credentials.client_id":"ignored"})");
    auto creds = agent.ExtractClientCredentials(cfg);
    EXPECT_EQ(creds.at("client_id"), "client1");
    EXPECT_EQ(creds.at("api_key"), "key1");
    EXPECT_EQ(creds.at("extra"), "v");
    EXPECT_FALSE(creds.count("credentials.client_id"));
    EXPECT_FALSE(creds.count("not_credentials.client_id"));
}

TEST(RemoteDataBatchProtectionAgentCredentialsTest, ExtractCredentialsIgnoresEmptyStrippedKey) {
    TestableRemoteDataBatchProtectionAgent agent;
    auto cfg = nlohmann::json::parse(R"({"credentials.":"bad","credentials.client_id":"client1"})");
    auto creds = agent.ExtractClientCredentials(cfg);
    EXPECT_EQ(creds.at("client_id"), "client1");
    EXPECT_FALSE(creds.count(""));
}

// Test basic initialization with valid configuration
TEST_F(RemoteDataBatchProtectionAgentTest, LoadsConfigFromFileAndFailsHealthCheck) {
    // Use default constructor to ensure config is loaded from file and HTTP client is created internally
    auto agent = TestableRemoteDataBatchProtectionAgent();

    // Create a (temp) config file with a localhost URL to avoid external network
    auto configuration_map = GetConfigurationMap(
        "{\"server_url\": \"http://localhost:8080\"}", "test_connection_config.json");
    std::string app_context = "{\"user_id\": \"test_user\"}";

    // init() should throw because health check will fail (we're using a real client with no server)
    // but it must parse config and extract values first
    EXPECT_THROW(agent.init("test_column", configuration_map, app_context, "test_key",
                            Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt),
                 DBPSException);

    // Test that initialization variables are properly set
    EXPECT_EQ(agent.get_column_name(), "test_column");
    EXPECT_EQ(agent.get_column_key_id(), "test_key");
    EXPECT_EQ(agent.get_datatype(), Type::BYTE_ARRAY);
    EXPECT_EQ(agent.get_compression_type(), CompressionCodec::UNCOMPRESSED);
    EXPECT_EQ(agent.get_app_context(), app_context);

    // Config path should be present and file exists
    EXPECT_TRUE(agent.get_configuration_map().find(TestableRemoteDataBatchProtectionAgent::k_connection_config_key_)
                != agent.get_configuration_map().end());
    EXPECT_TRUE(std::filesystem::exists(
        agent.get_configuration_map().at(TestableRemoteDataBatchProtectionAgent::k_connection_config_key_)));

    // Values extracted before health check
    EXPECT_EQ(agent.get_server_url(), "http://localhost:8080");
    EXPECT_EQ(agent.get_user_id(), "test_user");

    // Initialized status should indicate health check failure
    ASSERT_TRUE(agent.get_initialized().has_value());
    EXPECT_NE(agent.get_initialized()->find("healthz"), std::string::npos);
}

// Verify default pool configuration values are applied when not provided
TEST_F(RemoteDataBatchProtectionAgentTest, PoolConfigDefaultsAreApplied) {
    TestableRemoteDataBatchProtectionAgent agent;
    const nlohmann::json json = nlohmann::json::parse("{\"server_url\": \"http://localhost:8080\"}");
    auto cfg = agent.ExtractPoolConfig(json);
    EXPECT_EQ(cfg.max_pool_size, HttplibPoolRegistry::kDefaultMaxPoolSize);
    EXPECT_EQ(cfg.borrow_timeout.count(), HttplibPoolRegistry::kDefaultBorrowTimeout_ms.count());
    EXPECT_EQ(cfg.max_idle_time.count(), HttplibPoolRegistry::kDefaultMaxIdleTime_ms.count());
    EXPECT_EQ(cfg.connect_timeout.count(), HttplibPoolRegistry::kDefaultConnectTimeout_s.count());
    EXPECT_EQ(cfg.read_timeout.count(), HttplibPoolRegistry::kDefaultReadTimeout_s.count());
    EXPECT_EQ(cfg.write_timeout.count(), HttplibPoolRegistry::kDefaultWriteTimeout_s.count());
}

// Verify custom pool configuration values from JSON are applied
TEST_F(RemoteDataBatchProtectionAgentTest, PoolConfigCustomValuesAreApplied) {
    TestableRemoteDataBatchProtectionAgent agent;
    const std::string json_str =
        "{\n"
        "  \"server_url\": \"http://localhost:8080\",\n"
        "  \"connection_pool.max_pool_size\": 13,\n"
        "  \"connection_pool.borrow_timeout_milliseconds\": 250,\n"
        "  \"connection_pool.max_idle_time_milliseconds\": 45000,\n"
        "  \"connection_pool.connect_timeout_seconds\": 9,\n"
        "  \"connection_pool.read_timeout_seconds\": 44,\n"
        "  \"connection_pool.write_timeout_seconds\": 33\n"
        "}";
    const nlohmann::json json = nlohmann::json::parse(json_str);
    auto cfg = agent.ExtractPoolConfig(json);
    EXPECT_EQ(cfg.max_pool_size, 13u);
    EXPECT_EQ(cfg.borrow_timeout.count(), 250);
    EXPECT_EQ(cfg.max_idle_time.count(), 45000);
    EXPECT_EQ(cfg.connect_timeout.count(), 9);
    EXPECT_EQ(cfg.read_timeout.count(), 44);
    EXPECT_EQ(cfg.write_timeout.count(), 33);
}

// Verify a mix of provided and missing values results in custom + defaults accordingly
TEST_F(RemoteDataBatchProtectionAgentTest, PoolConfigMixedDefaultsAndCustom) {
    TestableRemoteDataBatchProtectionAgent agent;
    const std::string json_str =
        "{\n"
        "  \"server_url\": \"http://localhost:8080\",\n"
        "  \"connection_pool.max_pool_size\": 5,\n"
        "  \"connection_pool.read_timeout_seconds\": 7\n"
        "}";
    const nlohmann::json json = nlohmann::json::parse(json_str);

    auto cfg = agent.ExtractPoolConfig(json);

    // Provided values
    EXPECT_EQ(cfg.max_pool_size, 5u);
    EXPECT_EQ(cfg.read_timeout.count(), 7);

    // Defaults for missing values
    EXPECT_EQ(cfg.borrow_timeout.count(), HttplibPoolRegistry::kDefaultBorrowTimeout_ms.count());
    EXPECT_EQ(cfg.max_idle_time.count(), HttplibPoolRegistry::kDefaultMaxIdleTime_ms.count());
    EXPECT_EQ(cfg.connect_timeout.count(), HttplibPoolRegistry::kDefaultConnectTimeout_s.count());
    EXPECT_EQ(cfg.write_timeout.count(), HttplibPoolRegistry::kDefaultWriteTimeout_s.count());
}

// Verify malformed (wrong-typed) values throw
TEST_F(RemoteDataBatchProtectionAgentTest, PoolConfigMalformedValuesThrow) {
    TestableRemoteDataBatchProtectionAgent agent;
    const std::string json_str =
        "{\n"
        "  \"server_url\": \"http://localhost:8080\",\n"
        "  \"connection_pool.max_pool_size\": \"oops\",\n"
        "  \"connection_pool.borrow_timeout_milliseconds\": \"abc\",\n"
        "  \"connection_pool.max_idle_time_milliseconds\": true,\n"
        "  \"connection_pool.connect_timeout_seconds\": {},\n"
        "  \"connection_pool.read_timeout_seconds\": [],\n"
        "  \"connection_pool.write_timeout_seconds\": null\n"
        "}";
    const nlohmann::json json = nlohmann::json::parse(json_str);

    EXPECT_THROW(agent.ExtractPoolConfig(json), DBPSException);
}

// Verify num_worker_threads extraction (default/custom/malformed)
TEST_F(RemoteDataBatchProtectionAgentTest, NumWorkerThreadsDefaultIsZero) {
    TestableRemoteDataBatchProtectionAgent agent;
    const nlohmann::json json = nlohmann::json::parse("{\"server_url\": \"http://localhost:8080\"}");
    auto n = agent.ExtractNumWorkerThreads(json);
    EXPECT_EQ(n, 0u);
}

TEST_F(RemoteDataBatchProtectionAgentTest, NumWorkerThreadsCustomValue) {
    TestableRemoteDataBatchProtectionAgent agent;
    const nlohmann::json json = nlohmann::json::parse(
        "{\"server_url\": \"http://localhost:8080\", \"connection_pool.num_worker_threads\": 7}");
    auto n = agent.ExtractNumWorkerThreads(json);
    EXPECT_EQ(n, 7u);
}

TEST_F(RemoteDataBatchProtectionAgentTest, NumWorkerThreadsMalformedThrows) {
    TestableRemoteDataBatchProtectionAgent agent;
    const nlohmann::json json = nlohmann::json::parse(
        "{\"server_url\": \"http://localhost:8080\", \"connection_pool.num_worker_threads\": \"threads\"}");
    EXPECT_THROW(agent.ExtractNumWorkerThreads(json), DBPSException);
}

// Test decryption without initialization
TEST_F(RemoteDataBatchProtectionAgentTest, DecryptWithoutInit) {
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    // Don't call init() - leave agent uninitialized
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}};
    auto result = agent.Decrypt(test_data, encoding_attributes);
    
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(result->success());
    
    std::string error_msg = result->error_message();
    EXPECT_TRUE(error_msg.find("init() was not called") != std::string::npos);
}

// Test initialization with bad connection configurations
TEST_F(RemoteDataBatchProtectionAgentTest, EmptyConnectionConfig) {
    TestConnectionConfigFailures(GetConfigurationMap("", "empty_connection_config.json"));
}

TEST_F(RemoteDataBatchProtectionAgentTest, NonExistingConnectionConfigFile) {
    TestConnectionConfigFailures({{TestableRemoteDataBatchProtectionAgent::k_connection_config_key_, "foo"}});
}

TEST_F(RemoteDataBatchProtectionAgentTest, BadJsonConfigFile) {
    TestConnectionConfigFailures(GetConfigurationMap("foo", "bad_json_connection_config.json"));
}

// Test initialization with missing user ID
TEST_F(RemoteDataBatchProtectionAgentTest, MissingUserId) {
    auto agent = TestableRemoteDataBatchProtectionAgent();

    auto configuration_map = GetConfigurationMap(
        "{\"server_url\": \"http://localhost:8080\"}", "test_connection_config.json");
    std::string app_context = "{}"; // No user_id
    
    // init() should throw DBPSException for missing user ID
    EXPECT_THROW(agent.init("test_column", configuration_map, app_context, "test_key", 
                            Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt), 
                 DBPSException);
    
    // Test that the initialized_ state reflects the failure
    EXPECT_TRUE(agent.get_initialized().has_value());
    EXPECT_FALSE(agent.get_initialized()->empty());
    EXPECT_TRUE(agent.get_initialized()->find("user_id") != std::string::npos);
    
    // Test that Encrypt() returns a failed result with the initialization error
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}};
    auto result = agent.Encrypt(test_data, encoding_attributes);
    
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
    
    auto configuration_map = GetConfigurationMap(
        "{\"server_url\": \"http://localhost:8080\"}", "test_connection_config.json");
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    // init() should throw DBPSException for health check failure
    EXPECT_THROW(agent.init("test_column", configuration_map, app_context, "test_key", 
                            Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt), 
                 DBPSException);
    
    // Test that the initialized_ state reflects the failure
    EXPECT_TRUE(agent.get_initialized().has_value());
    EXPECT_FALSE(agent.get_initialized()->empty());
    EXPECT_TRUE(agent.get_initialized()->find("healthz") != std::string::npos);
    
    // Test that Encrypt() returns a failed result with the initialization error
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}};
    auto result = agent.Encrypt(test_data, encoding_attributes);
    
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
    
    auto configuration_map = GetConfigurationMap(
        "{\"server_url\": \"http://localhost:8080\"}", "test_connection_config.json");
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    // init() should not throw an exception for valid configuration
    EXPECT_NO_THROW(agent.init("test_column", configuration_map, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}};
    auto result = agent.Encrypt(test_data, encoding_attributes);
    
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
        "\"datatype_info\":{\"datatype\":\"BYTE_ARRAY\"},"
        "\"value_format\":{\"compression\":\"UNCOMPRESSED\",\"format\":\"PLAIN\"},"
        "\"value\":\"dGVzdF9kYXRh\""
        "}}", 
        ""
    );
    
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    auto configuration_map = GetConfigurationMap(
        "{\"server_url\": \"http://localhost:8080\"}", "test_connection_config.json");
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    // init() should not throw an exception for valid configuration
    EXPECT_NO_THROW(agent.init("test_column", configuration_map, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}};
    auto result = agent.Decrypt(test_data, encoding_attributes);
    
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

// Test decryption field validation mismatches
TEST_F(RemoteDataBatchProtectionAgentTest, DecryptionFieldMismatch) {
    struct TestCase {
        std::string response_json;
        std::string expected_error_field;
        std::string expected_request_value;
        std::string expected_response_value;
    };
    
    std::vector<TestCase> test_cases = {
        // Datatype mismatch
        {
            "{\"access\":{\"user_id\":\"test_user\",\"role\":\"EmailReader\",\"access_control\":\"granted\"},"
            "\"debug\":{\"reference_id\":\"123\"},"
            "\"data_batch\":{"
            "\"datatype_info\":{\"datatype\":\"INT32\"},"
            "\"value_format\":{\"compression\":\"UNCOMPRESSED\",\"format\":\"PLAIN\"},"
            "\"value\":\"dGVzdF9kYXRh\""
            "}}",
            "datatype mismatch",
            "INT32",
            "BYTE_ARRAY"
        },
        // Compression mismatch
        {
            "{\"access\":{\"user_id\":\"test_user\",\"role\":\"EmailReader\",\"access_control\":\"granted\"},"
            "\"debug\":{\"reference_id\":\"123\"},"
            "\"data_batch\":{"
            "\"datatype_info\":{\"datatype\":\"BYTE_ARRAY\"},"
            "\"value_format\":{\"compression\":\"GZIP\",\"format\":\"PLAIN\"},"
            "\"value\":\"dGVzdF9kYXRh\""
            "}}",
            "compression mismatch",
            "UNCOMPRESSED",
            "GZIP"
        }
    };
    
    for (const auto& test_case : test_cases) {
        auto mock_client = std::make_unique<MockHttpClient>();
        mock_client->health_response = {200, "OK", ""};
        mock_client->decrypt_response = MockHttpClient::MockResponse(200, test_case.response_json, "");
        
        auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client));
        
        auto configuration_map = GetConfigurationMap(
            "{\"server_url\": \"http://localhost:8080\"}", "test_connection_config.json");
        std::string app_context = "{\"user_id\": \"test_user\"}";
        
        // init() should not throw an exception for valid configuration
        EXPECT_NO_THROW(agent.init("test_column", configuration_map, app_context, "test_key", 
                                   Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt));
        
        std::vector<uint8_t> test_data = {1, 2, 3, 4};
        std::map<std::string, std::string> encoding_attributes = {
            {"page_type", "DATA_PAGE"},
            {"page_encoding", "PLAIN"},
            {"data_page_num_values", "4"}
        };
        auto result = agent.Decrypt(test_data, encoding_attributes);
        
        ASSERT_NE(result, nullptr);
        EXPECT_FALSE(result->success());
        
        // Check that the error message contains expected content
        std::string error_msg = result->error_message();
        EXPECT_TRUE(error_msg.find(test_case.expected_error_field) != std::string::npos);
        EXPECT_TRUE(error_msg.find(test_case.expected_request_value) != std::string::npos);
        EXPECT_TRUE(error_msg.find(test_case.expected_response_value) != std::string::npos);
    }
}

// Test encryption field validation mismatch
TEST_F(RemoteDataBatchProtectionAgentTest, EncryptionFieldMismatch) {
    mock_client_->health_response = {200, "OK", ""};
    mock_client_->encrypt_response = MockHttpClient::MockResponse(
        200, 
        "{\"access\":{\"user_id\":\"test_user\",\"role\":\"EmailReader\",\"access_control\":\"granted\"},"
        "\"debug\":{\"reference_id\":\"123\"},"
        "\"data_batch_encrypted\":{"
        "\"value_format\":{\"compression\":\"GZIP\"},"
        "\"value\":\"dGVzdF9kYXRh\""
        "}}", 
        ""
    );
    
    auto agent = TestableRemoteDataBatchProtectionAgent(std::move(mock_client_));
    
    auto configuration_map = GetConfigurationMap(
        "{\"server_url\": \"http://localhost:8080\"}", "test_connection_config.json");
    std::string app_context = "{\"user_id\": \"test_user\"}";
    
    // init() should not throw an exception for valid configuration
    EXPECT_NO_THROW(agent.init("test_column", configuration_map, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {
        {"page_type", "DATA_PAGE"},
        {"page_encoding", "PLAIN"},
        {"data_page_num_values", "4"}
    };
    auto result = agent.Encrypt(test_data, encoding_attributes);
    
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(result->success());
    
    // Check that the error message contains expected content
    std::string error_msg = result->error_message();
    EXPECT_TRUE(error_msg.find("encrypted_compression mismatch") != std::string::npos);
    EXPECT_TRUE(error_msg.find("UNCOMPRESSED") != std::string::npos);
    EXPECT_TRUE(error_msg.find("GZIP") != std::string::npos);
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
