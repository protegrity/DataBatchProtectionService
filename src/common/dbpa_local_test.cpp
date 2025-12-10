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

#include "dbpa_local.h"
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace dbps::external;

namespace {
    const std::map<std::string, std::string> DBPS_ENCRYPTION_METADATA = {
        {"dbps_agent_version", "v0.01_unittest"},
        {"encrypt_mode_dict_page", "per_block"}
    };
}

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
                               Type::UNDEFINED, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
    auto result = agent.Encrypt(test_data, encoding_attributes);
    
    ASSERT_NE(result, nullptr);
    EXPECT_TRUE(result->success());
    EXPECT_GT(result->size(), 0);
}

TEST_F(LocalDataBatchProtectionAgentTest, SuccessfulEncryptionCompressedDictionary) {
    LocalDataBatchProtectionAgent agent;
    
    std::map<std::string, std::string> connection_config;
    std::string app_context = R"({"user_id": "test_user"})";
    
    EXPECT_NO_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::GZIP, std::nullopt));
    
    // GZIP compressed data for strings "apple" and "banana"
    std::vector<uint8_t> test_data_gzip = {
        0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF,
        0x63, 0x65, 0x60, 0x60, 0x48, 0x2C, 0x28, 0xC8, 0x49, 0x65,
        0x03, 0x32, 0x92, 0x12, 0xF3, 0x80, 0x10, 0x00, 0xC7, 0xB8,
        0x50, 0xFC, 0x13, 0x00, 0x00, 0x00
    };
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
    auto result = agent.Encrypt(test_data_gzip, encoding_attributes);
    
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
                               Type::UNDEFINED, std::nullopt, CompressionCodec::UNCOMPRESSED, DBPS_ENCRYPTION_METADATA));
    
    std::vector<uint8_t> test_data = {1, 2, 3, 4};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
    auto result = agent.Decrypt(test_data, encoding_attributes);
    
    ASSERT_NE(result, nullptr);
    EXPECT_TRUE(result->success());
    EXPECT_GT(result->size(), 0);
}

// Test roundtrip encryption/decryption
TEST_F(LocalDataBatchProtectionAgentTest, RoundTripEncryptDecrypt) {
    LocalDataBatchProtectionAgent encrypt_agent;
    
    std::map<std::string, std::string> connection_config;
    std::string app_context = R"({"user_id": "test_user"})";
    
    EXPECT_NO_THROW(encrypt_agent.init("test_column", connection_config, app_context, "test_key", 
                                       Type::UNDEFINED, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt));
    
    // Original data to encrypt
    std::vector<uint8_t> original_data = {1, 2, 3, 4, 5};
    std::map<std::string, std::string> encoding_attributes = {{"page_encoding", "PLAIN"}, {"page_type", "DICTIONARY_PAGE"}};
    
    // Encrypt the data
    auto encrypt_result = encrypt_agent.Encrypt(original_data, encoding_attributes);
    
    ASSERT_NE(encrypt_result, nullptr);
    ASSERT_TRUE(encrypt_result->success());
    EXPECT_GT(encrypt_result->size(), 0);
    
    // Verify encryption_metadata is present in the result
    auto encryption_metadata = encrypt_result->encryption_metadata();
    ASSERT_TRUE(encryption_metadata.has_value());
    ASSERT_TRUE(encryption_metadata->find("dbps_agent_version") != encryption_metadata->end());
    ASSERT_TRUE(encryption_metadata->find("encrypt_mode_dict_page") != encryption_metadata->end());
    
    // Get the ciphertext
    auto ciphertext_span = encrypt_result->ciphertext();
    std::vector<uint8_t> ciphertext(ciphertext_span.begin(), ciphertext_span.end());
    
    // Create a new agent for decryption with the encryption_metadata from the encryption result
    LocalDataBatchProtectionAgent decrypt_agent;
    EXPECT_NO_THROW(decrypt_agent.init("test_column", connection_config, app_context, "test_key", 
                                       Type::UNDEFINED, std::nullopt, CompressionCodec::UNCOMPRESSED, encryption_metadata));
    
    // Decrypt the ciphertext
    auto decrypt_result = decrypt_agent.Decrypt(ciphertext, encoding_attributes);
    
    ASSERT_NE(decrypt_result, nullptr);
    ASSERT_TRUE(decrypt_result->success());
    
    // Verify the decrypted data matches the original
    auto plaintext_span = decrypt_result->plaintext();
    std::vector<uint8_t> decrypted_data(plaintext_span.begin(), plaintext_span.end());
    
    ASSERT_EQ(original_data.size(), decrypted_data.size());
    EXPECT_EQ(original_data, decrypted_data);
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
                            Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt), DBPSException);
}

// Test missing page_encoding in encoding_attributes
TEST_F(LocalDataBatchProtectionAgentTest, MissingPageEncoding) {
    LocalDataBatchProtectionAgent agent;
    
    std::map<std::string, std::string> connection_config;
    std::string app_context = R"({"user_id": "test_user"})";
    
    EXPECT_NO_THROW(agent.init("test_column", connection_config, app_context, "test_key", 
                               Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, std::nullopt));
    
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

