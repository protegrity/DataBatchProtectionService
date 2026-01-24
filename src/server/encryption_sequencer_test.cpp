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

#include "encryption_sequencer.h"
#include "compression_utils.h"
#include "../common/enums.h"
#include "../common/bytes_utils.h"
#include <iostream>
#include <cassert>
#include <string>
#include <map>
#include <variant>
#include <gtest/gtest.h>

using namespace dbps::compression;

using namespace dbps::external;

// TODO: Move this to a common test utility file.
// Methods that will pad byte arrays of strings (or pure bytes) with preceding
// bytes that specify the array length. Needed because this is how Parquet
// encodings represent their data.
std::vector<uint8_t> EncodeStringByteArray(const std::vector<std::string>& strings) {
    std::vector<uint8_t> result;
    for (const auto& str : strings) {
        uint32_t len = str.size();
        // Add 4-byte length prefix (little-endian)
        result.push_back(len & 0xFF);
        result.push_back((len >> 8) & 0xFF);
        result.push_back((len >> 16) & 0xFF);
        result.push_back((len >> 24) & 0xFF);
        // Add string data
        result.insert(result.end(), str.begin(), str.end());
    }
    return result;
}

std::vector<uint8_t> EncodePlainByteArray(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    uint32_t len = static_cast<uint32_t>(payload.size());
    out.push_back(static_cast<uint8_t>( len & 0xFF));
    out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// Test data constants - pure binary data
const std::vector<uint8_t> HELLO_WORLD_DATA = EncodeStringByteArray({"Hello, World!"});
const std::vector<uint8_t> BINARY_DATA = EncodePlainByteArray({0x00, 0x01, 0x02, 0x03, 0x04, 0x05});
const std::vector<uint8_t> SINGLE_CHAR_DATA = EncodeStringByteArray({"A"});
const std::vector<uint8_t> EMPTY_DATA = {};
const std::vector<uint8_t> FIXED_LEN_BYTE_ARRAY_DATA = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f'
};

// Test class that inherits from DataBatchEncryptionSequencer to access protected members
class TestDataBatchEncryptionSequencer : public DataBatchEncryptionSequencer {
public:
    // Forward constructor
    TestDataBatchEncryptionSequencer(
        const std::string& column_name,
        Type::type datatype,
        const std::optional<int>& datatype_length,
        CompressionCodec::type compression,
        Encoding::type encoding,
        const std::map<std::string, std::string>& encoding_attributes,
        CompressionCodec::type encrypted_compression,
        const std::string& key_id,
        const std::string& user_id,
        const std::string& application_context,
        const std::map<std::string, std::string>& encryption_metadata
    ) : DataBatchEncryptionSequencer(column_name, datatype, datatype_length, compression, encoding, encoding_attributes, encrypted_compression, key_id, user_id, application_context, encryption_metadata) {}
    
    // Public access to protected methods
    bool TestConvertEncodingAttributesToValues() {
        return ConvertEncodingAttributesToValues();
    }
    
    const AttributesMap& GetEncodingAttributesConverted() const {
        return encoding_attributes_converted_;
    }
};

// Test: encryption/decryption works correctly
TEST(EncryptionSequencer, EncryptionDecryption) {
    // Test 1: Basic encryption/decryption round trip
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column",     // column_name
            Type::BYTE_ARRAY,      // datatype
            std::nullopt,      // datatype_length
            CompressionCodec::UNCOMPRESSED,    // compression
            Encoding::PLAIN,           // encoding
            {{"page_type", "DICTIONARY_PAGE"}},   // encoding_attributes (mostly empty for basic test)
            CompressionCodec::UNCOMPRESSED,    // encrypted_compression
            "test_key_123",     // key_id
            "test_user",       // user_id
            "{}",               // application_context
            {}                  // encryption_metadata
        );
        
        // Test encryption
        bool encrypt_result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        ASSERT_TRUE(encrypt_result) << "Encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
    }
    
    // Test 2: Different key_id produces different encryption
    {
        DataBatchEncryptionSequencer sequencer1(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "key1", "test_user", "{}", {}
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "key2", "test_user", "{}", {}
        );
        
        
        bool result1 = sequencer1.DecodeAndEncrypt(HELLO_WORLD_DATA);
        bool result2 = sequencer2.DecodeAndEncrypt(HELLO_WORLD_DATA);
        
        ASSERT_TRUE(result1);
        ASSERT_TRUE(result2);
    }
    
    // Test 3: Same key_id produces consistent encryption
    {
        DataBatchEncryptionSequencer sequencer1(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "same_key", "test_user", "{}", {}
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "same_key", "test_user", "{}", {}
        );
        
        
        bool result1 = sequencer1.DecodeAndEncrypt(HELLO_WORLD_DATA);
        bool result2 = sequencer2.DecodeAndEncrypt(HELLO_WORLD_DATA);
        
        ASSERT_TRUE(result1);
        ASSERT_TRUE(result2);
    }
    
    // Test 4: Empty data encryption
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        
        // This should fail because empty input is rejected
        bool result = sequencer.DecodeAndEncrypt(EMPTY_DATA);
        EXPECT_FALSE(result) << "Empty data encryption should have failed";
    }
    
    // Test 5: Binary data encryption
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        
        // Binary data: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
        
        bool result = sequencer.DecodeAndEncrypt(BINARY_DATA);
        ASSERT_TRUE(result) << "Binary data encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
    }
    
}

// Test parameter validation
TEST(EncryptionSequencer, ParameterValidation) {
    // Test 1: Valid parameters, should succeed
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        bool result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        ASSERT_TRUE(result) << "Valid parameters test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
    }
    
    // Test 2: Invalid compression (should succeed with warning)
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::GZIP, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        bool result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        ASSERT_TRUE(result);
        EXPECT_TRUE(sequencer.error_stage_.empty());
    }
    
    // Test 3: Undefined encoding is supported
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::UNDEFINED, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        bool result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        ASSERT_TRUE(result) << "Encoding UNDEFINED should be supported: " << sequencer.error_message_;
        EXPECT_TRUE(sequencer.error_stage_.empty()) << "Unexpected error stage for supported encoding: " << sequencer.error_stage_;
    }
    
    // Test 4: All encodings now supported (including RLE)
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::RLE, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        bool result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        ASSERT_TRUE(result) << "Encoding RLE should now be supported: " << sequencer.error_message_;
        EXPECT_TRUE(sequencer.error_stage_.empty()) << "Unexpected error stage for supported encoding (RLE): " << sequencer.error_stage_;
    }
    
}

// Test input validation
TEST(EncryptionSequencer, InputValidation) {
    // Test 1: Empty plaintext
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        bool result = sequencer.DecodeAndEncrypt(EMPTY_DATA);
        EXPECT_FALSE(result) << "Empty plaintext test should have failed";
        EXPECT_EQ(sequencer.error_stage_, "validation") << "Wrong error stage for empty plaintext";
    }
    
    // Test 2: Empty ciphertext
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        bool result = sequencer.DecryptAndEncode(EMPTY_DATA);
        EXPECT_FALSE(result) << "Empty ciphertext test should have failed";
        EXPECT_EQ(sequencer.error_stage_, "validation") << "Wrong error stage for empty ciphertext";
    }
    
    // Test 3: Empty key_id
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "", "test_user", "{}", {}
        );
        bool result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        EXPECT_FALSE(result) << "Empty key_id test should have failed";
        EXPECT_EQ(sequencer.error_stage_, "validation") << "Wrong error stage for empty key_id";
    }

    // Test 4: Missing encryption_metadata
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}",
            {}  // encryption_metadata, setting it to empty map.
        );
        bool result = sequencer.DecryptAndEncode(HELLO_WORLD_DATA);
        EXPECT_FALSE(result) << "Missing encryption_metadata test should have failed";
        EXPECT_EQ(sequencer.error_stage_, "decrypt_version_check") << "Wrong error stage for missing encryption_metadata";
        EXPECT_TRUE(sequencer.error_message_.find("encryption_metadata must contain key") != std::string::npos) << "Wrong error message for missing encryption_metadata";
    }

    // Test 5: Incorrect encryption_metadata version
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}",
            {{"dbps_agent_version", "v0.09"}}  // encryption_metadata, setting it to incorrect version.
        );
        bool result = sequencer.DecryptAndEncode(HELLO_WORLD_DATA);
        EXPECT_FALSE(result) << "Incorrect encryption_metadata version test should have failed";
        EXPECT_EQ(sequencer.error_stage_, "decrypt_version_check") << "Wrong error stage for incorrect encryption_metadata version";
        EXPECT_TRUE(sequencer.error_message_.find("must match") != std::string::npos) << "Wrong error message for incorrect encryption_metadata version";
    }

}

// Test round-trip encryption/decryption
TEST(EncryptionSequencer, RoundTripEncryption) {
    // Test 1: Basic round trip - "Hello, World!"
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key_123", "test_user", "{}", {}
        );
        
        // Encrypt
        bool encrypt_result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        ASSERT_TRUE(encrypt_result) << "Round trip encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
        
        // Decrypt the encrypted result - need encryption_metadata with dbps_agent_version
        ASSERT_TRUE(sequencer.encryption_metadata_.size() > 0 && sequencer.encryption_metadata_.at("dbps_agent_version").length() > 0);
        bool decrypt_result = sequencer.DecryptAndEncode(sequencer.encrypted_result_);
        ASSERT_TRUE(decrypt_result) << "Round trip decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
        
        // Verify the decrypted result matches the original
        EXPECT_EQ(sequencer.decrypted_result_, HELLO_WORLD_DATA);
    } 
    
    // Test 2: Binary data round trip
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "binary_test_key", "test_user", "{}", {}
        );
        
        // Encrypt
        bool encrypt_result = sequencer.DecodeAndEncrypt(BINARY_DATA);  // Binary data: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
        ASSERT_TRUE(encrypt_result) << "Binary round trip encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
        
        // Decrypt the encrypted result - need encryption_metadata with dbps_agent_version
        ASSERT_TRUE(sequencer.encryption_metadata_.size() > 0 && sequencer.encryption_metadata_.at("dbps_agent_version").length() > 0);
        bool decrypt_result = sequencer.DecryptAndEncode(sequencer.encrypted_result_);
        ASSERT_TRUE(decrypt_result) << "Binary round trip decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
        
        // Verify the decrypted result matches the original
        EXPECT_EQ(sequencer.decrypted_result_, BINARY_DATA);
    }
    
    // Test 3: Single character round trip
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "single_char_key", "test_user", "{}", {}
        );
        
        // "A"
        
        // Encrypt
        bool encrypt_result = sequencer.DecodeAndEncrypt(SINGLE_CHAR_DATA);
        ASSERT_TRUE(encrypt_result) << "Single char round trip encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
        
        // Decrypt the encrypted result - need encryption_metadata with dbps_agent_version
        ASSERT_TRUE(sequencer.encryption_metadata_.size() > 0 && sequencer.encryption_metadata_.at("dbps_agent_version").length() > 0);
        bool decrypt_result = sequencer.DecryptAndEncode(sequencer.encrypted_result_);
        ASSERT_TRUE(decrypt_result) << "Single char round trip decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
        
        // Verify the decrypted result matches the original
        EXPECT_EQ(sequencer.decrypted_result_, SINGLE_CHAR_DATA);
    }
    
    // Test 4: Different keys produce different encrypted results
    {
        DataBatchEncryptionSequencer sequencer1(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "key1", "test_user", "{}", {}
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "key2", "test_user", "{}", {}
        );
        
        bool result1 = sequencer1.DecodeAndEncrypt(HELLO_WORLD_DATA);
        bool result2 = sequencer2.DecodeAndEncrypt(HELLO_WORLD_DATA);
        
        ASSERT_TRUE(result1);
        ASSERT_TRUE(result2);
        
        // Key-aware XOR encryption should produce different results for different keys
        EXPECT_NE(sequencer1.encrypted_result_, sequencer2.encrypted_result_);
        
        // But both should decrypt back to the same original - need encryption_metadata with dbps_agent_version
        ASSERT_TRUE(sequencer1.encryption_metadata_.size() > 0 && sequencer1.encryption_metadata_.at("dbps_agent_version").length() > 0);
        ASSERT_TRUE(sequencer2.encryption_metadata_.size() > 0 && sequencer2.encryption_metadata_.at("dbps_agent_version").length() > 0);
        bool decrypt1 = sequencer1.DecryptAndEncode(sequencer1.encrypted_result_);
        bool decrypt2 = sequencer2.DecryptAndEncode(sequencer2.encrypted_result_);
        
        ASSERT_TRUE(decrypt1);
        ASSERT_TRUE(decrypt2);
        
        EXPECT_EQ(sequencer1.decrypted_result_, HELLO_WORLD_DATA);
        EXPECT_EQ(sequencer2.decrypted_result_, HELLO_WORLD_DATA);
    }  
}

// Test result storage
TEST(EncryptionSequencer, ResultStorage) {
    // Test 1: Verify encrypted result is stored
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        
        bool result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        ASSERT_TRUE(result) << "Result storage encryption test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
        
        // Verify encrypted_result_ is not empty and is different from input
        EXPECT_FALSE(sequencer.encrypted_result_.empty());
        
        EXPECT_NE(sequencer.encrypted_result_, HELLO_WORLD_DATA);
    }
    
    // Test 2: Verify decrypted result is stored
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {}
        );
        
        // First encrypt something
        bool encrypt_result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        ASSERT_TRUE(encrypt_result) << "Result storage decryption test failed during encryption";
        
        // Then decrypt it - need encryption_metadata with dbps_agent_version
        ASSERT_TRUE(sequencer.encryption_metadata_.size() > 0 && sequencer.encryption_metadata_.at("dbps_agent_version").length() > 0);
        bool decrypt_result = sequencer.DecryptAndEncode(sequencer.encrypted_result_);
        ASSERT_TRUE(decrypt_result) << "Result storage decryption test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
        
        // Verify decrypted_result_ is not empty and matches original
        EXPECT_FALSE(sequencer.decrypted_result_.empty());
        
        EXPECT_EQ(sequencer.decrypted_result_, HELLO_WORLD_DATA);
    }
    
}

// Test BOOLEAN type uses per-block encryption (not per-value)
TEST(EncryptionSequencer, BooleanTypeUsesPerBlockEncryption) {
    // BOOLEAN is not supported for per-value encryption and always defaults to per-block encryption
    std::vector<uint8_t> boolean_data = {0xB4, 0xFF, 0x00};  // some boolean bit-packed data
    
    DataBatchEncryptionSequencer sequencer(
        "bool_column",
        Type::BOOLEAN,
        std::nullopt,
        CompressionCodec::UNCOMPRESSED,
        Encoding::PLAIN,
        {{"page_type", "DICTIONARY_PAGE"}},
        CompressionCodec::UNCOMPRESSED,
        "test_key",
        "test_user",
        "{}",
        {}
    );
    
    bool result = sequencer.DecodeAndEncrypt(boolean_data);
    ASSERT_TRUE(result) << "BOOLEAN encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
    
    // Verify per-block encryption mode as used.
    ASSERT_TRUE(sequencer.encryption_metadata_.count("encrypt_mode_dict_page") == 1);
    EXPECT_EQ(sequencer.encryption_metadata_.at("encrypt_mode_dict_page"), "per_block");
    
    // Verify round-trip works
    bool decrypt_result = sequencer.DecryptAndEncode(sequencer.encrypted_result_);
    ASSERT_TRUE(decrypt_result) << "BOOLEAN decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
    EXPECT_EQ(sequencer.decrypted_result_, boolean_data);
}

// Test RLE_DICTIONARY encoding uses per-block encryption (not per-value)
TEST(EncryptionSequencer, RleDictionaryEncodingUsesPerBlockEncryption) {
    // RLE_DICTIONARY is not supported for per-value encryption since the values are not present in the data, only references to them
    std::vector<uint8_t> rle_dict_data = {0x02, 0x00, 0x00, 0x00, 0x01};  // some RLE dictionary encoded data
    
    DataBatchEncryptionSequencer sequencer(
        "dict_column",
        Type::INT32,
        std::nullopt,
        CompressionCodec::UNCOMPRESSED,
        Encoding::RLE_DICTIONARY,
        {{"page_type", "DICTIONARY_PAGE"}},
        CompressionCodec::UNCOMPRESSED,
        "test_key",
        "test_user",
        "{}",
        {}
    );
    
    bool result = sequencer.DecodeAndEncrypt(rle_dict_data);
    ASSERT_TRUE(result) << "RLE_DICTIONARY encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
    
    // Verify it used per-block encryption mode
    ASSERT_TRUE(sequencer.encryption_metadata_.count("encrypt_mode_dict_page") == 1);
    EXPECT_EQ(sequencer.encryption_metadata_.at("encrypt_mode_dict_page"), "per_block");
    
    // Verify round-trip works
    bool decrypt_result = sequencer.DecryptAndEncode(sequencer.encrypted_result_);
    ASSERT_TRUE(decrypt_result) << "RLE_DICTIONARY decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_;
    EXPECT_EQ(sequencer.decrypted_result_, rle_dict_data);
}

// Test FIXED_LEN_BYTE_ARRAY validation
TEST(EncryptionSequencer, FixedLenByteArrayValidation) {
    
    // Helper function to test validation failure
    auto testValidationFailure = [&](const std::optional<int>& datatype_length, const std::string& expected_msg) -> bool {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::FIXED_LEN_BYTE_ARRAY, datatype_length, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key_123", "test_user", "{}", {}
        );
        
        bool result = sequencer.DecodeAndEncrypt(HELLO_WORLD_DATA);
        if (result) {
            std::cout << "ERROR: Should have failed validation" << std::endl;
            return false;
        }
        
        if (sequencer.error_stage_ != "parameter_validation" || 
            sequencer.error_message_.find(expected_msg) == std::string::npos) {
            std::cout << "ERROR: Expected: " << expected_msg << std::endl;
            std::cout << "Got: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        return true;
    };
    
    // Test invalid cases
    EXPECT_TRUE(testValidationFailure(std::nullopt, "FIXED_LEN_BYTE_ARRAY datatype requires datatype_length parameter"));
    EXPECT_TRUE(testValidationFailure(-1, "FIXED_LEN_BYTE_ARRAY datatype_length must be positive"));
    EXPECT_TRUE(testValidationFailure(0, "FIXED_LEN_BYTE_ARRAY datatype_length must be positive"));

    // Test valid case (should pass parameter validation)
    DataBatchEncryptionSequencer sequencer("test_column", Type::FIXED_LEN_BYTE_ARRAY, 16, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key_123", "test_user", "{}", {});
    bool result = sequencer.DecodeAndEncrypt(FIXED_LEN_BYTE_ARRAY_DATA);
    
    if (!result && sequencer.error_stage_ == "parameter_validation") {
        ADD_FAILURE() << "Valid datatype_length should pass parameter validation";
    }
}


// Helper function to check if an encoding attribute variant contains expected value
template<typename T>
bool CheckEncodingAttribValue(const AttributesMap& converted,
                      const std::string& key, const T& expected) {
    auto it = converted.find(key);
    if (it == converted.end()) {
        return false;
    }
    
    try {
        const T& actual = std::get<T>(it->second);
        return actual == expected;
    } catch (const std::bad_variant_access&) {
        return false;
    }
}

TEST(EncryptionSequencer, ConvertEncodingAttributesToValues_Positive) {
    std::cout << "Testing ConvertEncodingAttributesToValues - Positive cases..." << std::endl;
    
    // Test DATA_PAGE_V2 with the required attributes
    std::map<std::string, std::string> attribs_v2 = {
        {"page_type", "DATA_PAGE_V2"},
        {"data_page_num_values", "100"},
        {"data_page_max_definition_level", "2"},
        {"data_page_max_repetition_level", "1"},
        {"page_v2_definition_levels_byte_length", "50"},
        {"page_v2_repetition_levels_byte_length", "25"},
        {"page_v2_num_nulls", "10"},
        {"page_v2_is_compressed", "true"}
    };
    
    TestDataBatchEncryptionSequencer sequencer_v2("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, attribs_v2, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {});
    ASSERT_TRUE(sequencer_v2.TestConvertEncodingAttributesToValues())
        << "DATA_PAGE_V2 conversion failed: " << sequencer_v2.error_stage_ << " - " << sequencer_v2.error_message_;
    
    // Verify converted values for DATA_PAGE_V2
    const auto& converted_v2 = sequencer_v2.GetEncodingAttributesConverted();
    EXPECT_TRUE(CheckEncodingAttribValue(converted_v2, "page_type", std::string("DATA_PAGE_V2")));
    EXPECT_TRUE(CheckEncodingAttribValue(converted_v2, "data_page_num_values", int32_t(100)));
    EXPECT_TRUE(CheckEncodingAttribValue(converted_v2, "page_v2_is_compressed", true));
    
    // Test DATA_PAGE_V1 with the required attributes
    std::map<std::string, std::string> attribs_v1 = {
        {"page_type", "DATA_PAGE_V1"},
        {"data_page_num_values", "200"},
        {"data_page_max_definition_level", "3"},
        {"data_page_max_repetition_level", "2"},
        {"page_v1_definition_level_encoding", "RLE"},
        {"page_v1_repetition_level_encoding", "BIT_PACKED"}
    };
    
    TestDataBatchEncryptionSequencer sequencer_v1("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, attribs_v1, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {});
    ASSERT_TRUE(sequencer_v1.TestConvertEncodingAttributesToValues())
        << "DATA_PAGE_V1 conversion failed: " << sequencer_v1.error_stage_ << " - " << sequencer_v1.error_message_;
    
    // Verify converted values for DATA_PAGE_V1
    const auto& converted_v1 = sequencer_v1.GetEncodingAttributesConverted();
    EXPECT_TRUE(CheckEncodingAttribValue(converted_v1, "page_type", std::string("DATA_PAGE_V1")));
    EXPECT_TRUE(CheckEncodingAttribValue(converted_v1, "data_page_num_values", int32_t(200)));
    EXPECT_TRUE(CheckEncodingAttribValue(converted_v1, "page_v1_definition_level_encoding", std::string("RLE")));
}

TEST(EncryptionSequencer, ConvertEncodingAttributesToValues_Negative) {
    std::cout << "Testing ConvertEncodingAttributesToValues - Negative cases..." << std::endl;
    
    // Test missing page_type
    std::map<std::string, std::string> empty_attribs;
    TestDataBatchEncryptionSequencer sequencer1("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, empty_attribs, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {});
    EXPECT_FALSE(sequencer1.TestConvertEncodingAttributesToValues());
    EXPECT_EQ(sequencer1.error_stage_, "encoding_attribute_conversion");
    
    // Test invalid int conversion
    std::map<std::string, std::string> invalid_int = {
        {"page_type", "DATA_PAGE_V2"},
        {"data_page_num_values", "not_a_number"},
        {"data_page_max_definition_level", "2"},
        {"data_page_max_repetition_level", "1"},
        {"page_v2_definition_levels_byte_length", "50"},
        {"page_v2_repetition_levels_byte_length", "25"},
        {"page_v2_num_nulls", "10"},
        {"page_v2_is_compressed", "true"}
    };
    
    TestDataBatchEncryptionSequencer sequencer2("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, invalid_int, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {});
    EXPECT_FALSE(sequencer2.TestConvertEncodingAttributesToValues());
    EXPECT_EQ(sequencer2.error_stage_, "encoding_attribute_conversion");
    
    // Test invalid bool conversion
    std::map<std::string, std::string> invalid_bool = {
        {"page_type", "DATA_PAGE_V2"},
        {"data_page_num_values", "100"},
        {"data_page_max_definition_level", "2"},
        {"data_page_max_repetition_level", "1"},
        {"page_v2_definition_levels_byte_length", "50"},
        {"page_v2_repetition_levels_byte_length", "25"},
        {"page_v2_num_nulls", "10"},
        {"page_v2_is_compressed", "maybe"}
    };
    
    TestDataBatchEncryptionSequencer sequencer3("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Encoding::PLAIN, invalid_bool, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}", {});
    EXPECT_FALSE(sequencer3.TestConvertEncodingAttributesToValues());
    EXPECT_EQ(sequencer3.error_stage_, "encoding_attribute_conversion");
}
