#include "dbpa_local.h"
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace dbps::external;

// Test fixture for LocalDataBatchProtectionAgent tests
class LocalDataBatchProtectionAgentTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common test setup if needed
    }
};

// Test successful initialization and encryption
TEST_F(LocalDataBatchProtectionAgentTest, SuccessfulEncryption) {
    LocalDataBatchProtectionAgent agent;
    
    std::map<std::string, std::string> connection_config;
    std::string app_context = R"({"user_id": "test_user"})";
    
    EXPECT_NO_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
    auto result = agent.Encrypt(test_data, encoding_attributes);
    
    ASSERT_NE(result, nullptr);
    EXPECT_TRUE(result->success());
    EXPECT_GT(result->size(), 0);
}

// Test successful initialization and decryption
TEST_F(LocalDataBatchProtectionAgentTest, SuccessfulDecryption) {
    LocalDataBatchProtectionAgent agent;
    
    std::map<std::string, std::string> connection_config;
    std::string app_context = R"({"user_id": "test_user"})";
    
    EXPECT_NO_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
    auto result = agent.Decrypt(test_data, encoding_attributes);
    
    ASSERT_NE(result, nullptr);
    EXPECT_TRUE(result->success());
    EXPECT_GT(result->size(), 0);
}

// Test encryption without initialization
TEST_F(LocalDataBatchProtectionAgentTest, EncryptWithoutInit) {
    LocalDataBatchProtectionAgent agent;
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
    auto result = agent.Encrypt(test_data, encoding_attributes);
    
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(result->success());
    
    std::string error_msg = result->error_message();
    EXPECT_TRUE(error_msg.find("init() was not called") != std::string::npos);
}

// Test decryption without initialization
TEST_F(LocalDataBatchProtectionAgentTest, DecryptWithoutInit) {
    LocalDataBatchProtectionAgent agent;
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
    auto result = agent.Decrypt(test_data, encoding_attributes);
    
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(result->success());
    
    std::string error_msg = result->error_message();
    EXPECT_TRUE(error_msg.find("init() was not called") != std::string::npos);
}

// Test missing user_id in app_context
TEST_F(LocalDataBatchProtectionAgentTest, MissingUserId) {
    LocalDataBatchProtectionAgent agent;
    
    std::map<std::string, std::string> connection_config;
    std::string app_context = R"({"role": "admin"})";
    
    EXPECT_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                            Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED), DBPSException);
}

// Test missing page_encoding in encoding_attributes
TEST_F(LocalDataBatchProtectionAgentTest, MissingPageEncoding) {
    LocalDataBatchProtectionAgent agent;
    
    std::map<std::string, std::string> connection_config;
    std::string app_context = R"({"user_id": "test_user"})";
    
    EXPECT_NO_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_type", "DICTIONARY_PAGE"}};
    auto result = agent.Encrypt(test_data, encoding_attributes);
    
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(result->success());
    EXPECT_TRUE(result->error_message().find("page_encoding") != std::string::npos);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

