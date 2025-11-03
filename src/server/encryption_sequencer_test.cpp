#include "encryption_sequencer.h"
#include "../common/enums.h"
#include <iostream>
#include <cassert>
#include <string>
#include <map>
#include <variant>

using namespace dbps::external;

// TODO: Move this to a common test utility file.
// Methods that will pad byte arrays of strings (or pure bytes) with preceding
// bytes that specify the array length. Needed because this is how Parquet
// formats their data.
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
        Format::type format,
        const std::map<std::string, std::string>& encoding_attributes,
        CompressionCodec::type encrypted_compression,
        const std::string& key_id,
        const std::string& user_id,
        const std::string& application_context
    ) : DataBatchEncryptionSequencer(column_name, datatype, datatype_length, compression, format, encoding_attributes, encrypted_compression, key_id, user_id, application_context) {}
    
    // Public access to protected methods
    bool TestConvertEncodingAttributesToValues() {
        return ConvertEncodingAttributesToValues();
    }
    
    const std::map<std::string, std::variant<int32_t, bool, std::string>>& GetEncodingAttributesConverted() const {
        return encoding_attributes_converted_;
    }
};

// Test helper function to print test results
void PrintTestResult(const std::string& test_name, bool passed) {
    std::cout << (passed ? "PASS" : "FAIL") << ": " << test_name << std::endl;
}

// Test helper function to check if encryption/decryption works correctly
bool TestEncryptionDecryption() {
    // Test 1: Basic encryption/decryption round trip
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column",     // column_name
            Type::BYTE_ARRAY,      // datatype
            std::nullopt,      // datatype_length
            CompressionCodec::UNCOMPRESSED,    // compression
            Format::PLAIN,           // format
            {{"page_type", "DICTIONARY_PAGE"}},   // encoding_attributes (mostly empty for basic test)
            CompressionCodec::UNCOMPRESSED,    // encrypted_compression
            "test_key_123",     // key_id
            "test_user",       // user_id
            "{}"               // application_context
        );
        
        // Test encryption
        bool encrypt_result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA);
        if (!encrypt_result) {
            std::cout << "Encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Different key_id produces different encryption
    {
        DataBatchEncryptionSequencer sequencer1(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "key1", "test_user", "{}"
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "key2", "test_user", "{}"
        );
        
        
        bool result1 = sequencer1.ConvertAndEncrypt(HELLO_WORLD_DATA);
        bool result2 = sequencer2.ConvertAndEncrypt(HELLO_WORLD_DATA);
        
        if (!result1 || !result2) {
            std::cout << "Different key encryption test failed" << std::endl;
            return false;
        }
    }
    
    // Test 3: Same key_id produces consistent encryption
    {
        DataBatchEncryptionSequencer sequencer1(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "same_key", "test_user", "{}"
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "same_key", "test_user", "{}"
        );
        
        
        bool result1 = sequencer1.ConvertAndEncrypt(HELLO_WORLD_DATA);
        bool result2 = sequencer2.ConvertAndEncrypt(HELLO_WORLD_DATA);
        
        if (!result1 || !result2) {
            std::cout << "Same key encryption test failed" << std::endl;
            return false;
        }
    }
    
    // Test 4: Empty data encryption
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        
        // This should fail because empty input is rejected
        bool result = sequencer.ConvertAndEncrypt(EMPTY_DATA);
        if (result) {
            std::cout << "Empty data encryption should have failed" << std::endl;
            return false;
        }
    }
    
    // Test 5: Binary data encryption
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        
        // Binary data: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
        
        bool result = sequencer.ConvertAndEncrypt(BINARY_DATA);
        if (!result) {
            std::cout << "Binary data encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test parameter validation
bool TestParameterValidation() {
    // Test 1: Valid parameters, should succeed
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        bool result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA);
        if (!result) {
            std::cout << "Valid parameters test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Invalid compression (should succeed with warning)
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::GZIP, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        bool result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA);
        if (!result) {
            return false;
        }
        // Should not have error stage since it succeeded
        if (!sequencer.error_stage_.empty()) {
            return false;
        }
    }
    
    // Test 3: Undefined format is supported
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::UNDEFINED, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        bool result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA);
        if (!result) {
            std::cout << "Format UNDEFINED should be supported: " << sequencer.error_message_ << std::endl;
            return false;
        }
        // Should succeed with no error stage
        if (!sequencer.error_stage_.empty()) {
            std::cout << "Unexpected error stage for supported format: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    // Test 4: All formats now supported (including RLE)
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::RLE, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        bool result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA);
        if (!result) {
            std::cout << "Format RLE should now be supported: " << sequencer.error_message_ << std::endl;
            return false;
        }
        // Should succeed with no error stage
        if (!sequencer.error_stage_.empty()) {
            std::cout << "Unexpected error stage for supported format (RLE): " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test input validation
bool TestInputValidation() {
    // Test 1: Empty plaintext
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        bool result = sequencer.ConvertAndEncrypt(EMPTY_DATA);
        if (result) {
            std::cout << "Empty plaintext test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "validation") {
            std::cout << "Wrong error stage for empty plaintext: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    // Test 2: Empty ciphertext
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        bool result = sequencer.ConvertAndDecrypt(EMPTY_DATA);
        if (result) {
            std::cout << "Empty ciphertext test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "validation") {
            std::cout << "Wrong error stage for empty ciphertext: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    // Test 3: Empty key_id
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "", "test_user", "{}"
        );
        bool result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA);
        if (result) {
            std::cout << "Empty key_id test should have failed" << std::endl;
            return false;
        }
        if (sequencer.error_stage_ != "validation") {
            std::cout << "Wrong error stage for empty key_id: " << sequencer.error_stage_ << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test round-trip encryption/decryption
bool TestRoundTripEncryption() {
    // Test 1: Basic round trip - "Hello, World!"
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key_123", "test_user", "{}"
        );
        
        // Encrypt
        bool encrypt_result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA); // "Hello, World!"
        if (!encrypt_result) {
            std::cout << "Round trip encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Decrypt the encrypted result
        bool decrypt_result = sequencer.ConvertAndDecrypt(sequencer.encrypted_result_);
        if (!decrypt_result) {
            std::cout << "Round trip decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify the decrypted result matches the original
        if (sequencer.decrypted_result_ != HELLO_WORLD_DATA) {
            std::cout << "Round trip failed: decrypted result does not match original" << std::endl;
            return false;
        }
    }
    
    // Test 2: Binary data round trip
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "binary_test_key", "test_user", "{}"
        );
        
        // Encrypt
        bool encrypt_result = sequencer.ConvertAndEncrypt(BINARY_DATA); // Binary data: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
        if (!encrypt_result) {
            std::cout << "Binary round trip encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Decrypt the encrypted result
        bool decrypt_result = sequencer.ConvertAndDecrypt(sequencer.encrypted_result_);
        if (!decrypt_result) {
            std::cout << "Binary round trip decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify the decrypted result matches the original
        if (sequencer.decrypted_result_ != BINARY_DATA) {
            std::cout << "Binary round trip failed: decrypted result does not match original" << std::endl;
            return false;
        }
    }
    
    // Test 3: Single character round trip
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "single_char_key", "test_user", "{}"
        );
        
        // "A"
        
        // Encrypt
        bool encrypt_result = sequencer.ConvertAndEncrypt(SINGLE_CHAR_DATA);
        if (!encrypt_result) {
            std::cout << "Single char round trip encryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Decrypt the encrypted result
        bool decrypt_result = sequencer.ConvertAndDecrypt(sequencer.encrypted_result_);
        if (!decrypt_result) {
            std::cout << "Single char round trip decryption failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify the decrypted result matches the original
        if (sequencer.decrypted_result_ != SINGLE_CHAR_DATA) {
            std::cout << "Single char round trip failed: decrypted result does not match original" << std::endl;
            return false;
        }
    }
    
    // Test 4: Different keys produce different encrypted results
    {
        DataBatchEncryptionSequencer sequencer1(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "key1", "test_user", "{}"
        );
        
        DataBatchEncryptionSequencer sequencer2(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "key2", "test_user", "{}"
        );
        
        bool result1 = sequencer1.ConvertAndEncrypt(HELLO_WORLD_DATA);
        bool result2 = sequencer2.ConvertAndEncrypt(HELLO_WORLD_DATA);
        
        if (!result1 || !result2) {
            std::cout << "Different keys test failed during encryption" << std::endl;
            return false;
        }
        
        // Key-aware XOR encryption should produce different results for different keys
        if (sequencer1.encrypted_result_ == sequencer2.encrypted_result_) {
            std::cout << "Simple XOR encryption should produce different results for different keys" << std::endl;
            return false;
        }
        
        // But both should decrypt back to the same original
        bool decrypt1 = sequencer1.ConvertAndDecrypt(sequencer1.encrypted_result_);
        bool decrypt2 = sequencer2.ConvertAndDecrypt(sequencer2.encrypted_result_);
        
        if (!decrypt1 || !decrypt2) {
            std::cout << "Different keys test failed during decryption" << std::endl;
            return false;
        }
        
        if (sequencer1.decrypted_result_ != HELLO_WORLD_DATA || sequencer2.decrypted_result_ != HELLO_WORLD_DATA) {
            std::cout << "Different keys test: decrypted results should match original" << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test result storage
bool TestResultStorage() {
    // Test 1: Verify encrypted result is stored
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        
        bool result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA);
        if (!result) {
            std::cout << "Result storage encryption test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify encrypted_result_ is not empty and is different from input
        if (sequencer.encrypted_result_.empty()) {
            std::cout << "encrypted_result_ should not be empty" << std::endl;
            return false;
        }
        
        if (sequencer.encrypted_result_ == HELLO_WORLD_DATA) {
            std::cout << "encrypted_result_ should be different from input" << std::endl;
            return false;
        }
    }
    
    // Test 2: Verify decrypted result is stored
    {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}"
        );
        
        // First encrypt something
        bool encrypt_result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA);
        if (!encrypt_result) {
            std::cout << "Result storage decryption test failed during encryption" << std::endl;
            return false;
        }
        
        // Then decrypt it
        bool decrypt_result = sequencer.ConvertAndDecrypt(sequencer.encrypted_result_);
        if (!decrypt_result) {
            std::cout << "Result storage decryption test failed: " << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
            return false;
        }
        
        // Verify decrypted_result_ is not empty and matches original
        if (sequencer.decrypted_result_.empty()) {
            std::cout << "decrypted_result_ should not be empty" << std::endl;
            return false;
        }
        
        if (sequencer.decrypted_result_ != HELLO_WORLD_DATA) {
            std::cout << "decrypted_result_ should match original input" << std::endl;
            return false;
        }
    }
    
    return true;
}

// Test FIXED_LEN_BYTE_ARRAY validation
bool TestFixedLenByteArrayValidation() {
    
    // Helper function to test validation failure
    auto testValidationFailure = [&](const std::optional<int>& datatype_length, const std::string& expected_msg) -> bool {
        DataBatchEncryptionSequencer sequencer(
            "test_column", Type::FIXED_LEN_BYTE_ARRAY, datatype_length, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key_123", "test_user", "{}"
        );
        
        bool result = sequencer.ConvertAndEncrypt(HELLO_WORLD_DATA);
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
    if (!testValidationFailure(std::nullopt, "FIXED_LEN_BYTE_ARRAY datatype requires datatype_length parameter")) return false;
    if (!testValidationFailure(-1, "FIXED_LEN_BYTE_ARRAY datatype_length must be positive")) return false;
    if (!testValidationFailure(0, "FIXED_LEN_BYTE_ARRAY datatype_length must be positive")) return false;

    // Test valid case (should pass parameter validation)
    DataBatchEncryptionSequencer sequencer("test_column", Type::FIXED_LEN_BYTE_ARRAY, 16, CompressionCodec::UNCOMPRESSED, Format::PLAIN, {{"page_type", "DICTIONARY_PAGE"}}, CompressionCodec::UNCOMPRESSED, "test_key_123", "test_user", "{}");
    bool result = sequencer.ConvertAndEncrypt(FIXED_LEN_BYTE_ARRAY_DATA);
    
    if (!result && sequencer.error_stage_ == "parameter_validation") {
        std::cout << "ERROR: Valid datatype_length should pass parameter validation" << std::endl;
        return false;
    }
    
    return true;
}


// Helper function to check if an encoding attribute variant contains expected value
template<typename T>
bool CheckEncodingAttribValue(const std::map<std::string, std::variant<int32_t, bool, std::string>>& converted,
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

bool TestConvertEncodingAttributesToValuesComplete() {
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
    
    TestDataBatchEncryptionSequencer sequencer_v2("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, attribs_v2, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}");
    if (!sequencer_v2.TestConvertEncodingAttributesToValues()) {
        std::cout << "ERROR: DATA_PAGE_V2 conversion failed: " << sequencer_v2.error_stage_ << " - " << sequencer_v2.error_message_ << std::endl;
        return false;
    }
    
    // Verify converted values for DATA_PAGE_V2
    const auto& converted_v2 = sequencer_v2.GetEncodingAttributesConverted();
    if (!CheckEncodingAttribValue(converted_v2, "page_type", std::string("DATA_PAGE_V2"))) {
        std::cout << "ERROR: page_type not converted correctly for DATA_PAGE_V2" << std::endl;
        return false;
    }
    if (!CheckEncodingAttribValue(converted_v2, "data_page_num_values", int32_t(100))) {
        std::cout << "ERROR: data_page_num_values not converted correctly" << std::endl;
        return false;
    }
    if (!CheckEncodingAttribValue(converted_v2, "page_v2_is_compressed", true)) {
        std::cout << "ERROR: page_v2_is_compressed not converted correctly" << std::endl;
        return false;
    }
    
    // Test DATA_PAGE_V1 with the required attributes
    std::map<std::string, std::string> attribs_v1 = {
        {"page_type", "DATA_PAGE_V1"},
        {"data_page_num_values", "200"},
        {"data_page_max_definition_level", "3"},
        {"data_page_max_repetition_level", "2"},
        {"page_v1_definition_level_encoding", "RLE"},
        {"page_v1_repetition_level_encoding", "BIT_PACKED"}
    };
    
    TestDataBatchEncryptionSequencer sequencer_v1("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, attribs_v1, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}");
    if (!sequencer_v1.TestConvertEncodingAttributesToValues()) {
        std::cout << "ERROR: DATA_PAGE_V1 conversion failed: " << sequencer_v1.error_stage_ << " - " << sequencer_v1.error_message_ << std::endl;
        return false;
    }
    
    // Verify converted values for DATA_PAGE_V1
    const auto& converted_v1 = sequencer_v1.GetEncodingAttributesConverted();
    if (!CheckEncodingAttribValue(converted_v1, "page_type", std::string("DATA_PAGE_V1"))) {
        std::cout << "ERROR: page_type not converted correctly for DATA_PAGE_V1" << std::endl;
        return false;
    }
    if (!CheckEncodingAttribValue(converted_v1, "data_page_num_values", int32_t(200))) {
        std::cout << "ERROR: data_page_num_values not converted correctly" << std::endl;
        return false;
    }
    if (!CheckEncodingAttribValue(converted_v1, "page_v1_definition_level_encoding", std::string("RLE"))) {
        std::cout << "ERROR: page_v1_definition_level_encoding not converted correctly" << std::endl;
        return false;
    }
        
    return true;
}

bool TestConvertEncodingAttributesToValuesInvalid() {
    std::cout << "Testing ConvertEncodingAttributesToValues - Negative cases..." << std::endl;
    
    // Test missing page_type
    std::map<std::string, std::string> empty_attribs;
    TestDataBatchEncryptionSequencer sequencer1("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, empty_attribs, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}");
    if (sequencer1.TestConvertEncodingAttributesToValues() || sequencer1.error_stage_ != "encoding_attribute_validation") {
        std::cout << "ERROR: Missing page_type should fail with encoding_attribute_validation error" << std::endl;
        return false;
    }
    
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
    
    TestDataBatchEncryptionSequencer sequencer2("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, invalid_int, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}");
    if (sequencer2.TestConvertEncodingAttributesToValues() || sequencer2.error_stage_ != "encoding_attribute_conversion") {
        std::cout << "ERROR: Invalid int should fail with encoding_attribute_conversion error" << std::endl;
        return false;
    }
    
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
    
    TestDataBatchEncryptionSequencer sequencer3("test_column", Type::BYTE_ARRAY, std::nullopt, CompressionCodec::UNCOMPRESSED, Format::PLAIN, invalid_bool, CompressionCodec::UNCOMPRESSED, "test_key", "test_user", "{}");
    if (sequencer3.TestConvertEncodingAttributesToValues() || sequencer3.error_stage_ != "encoding_attribute_conversion") {
        std::cout << "ERROR: Invalid bool should fail with encoding_attribute_conversion error" << std::endl;
        return false;
    }
    
    return true;
}

int main() {
    std::cout << "Running DataBatchEncryptionSequencer tests..." << std::endl;
    std::cout << "=============================================" << std::endl;
    
    bool all_tests_passed = true;
    
    // Run all test suites
    all_tests_passed &= TestParameterValidation();
    PrintTestResult("Parameter Validation", all_tests_passed);
    
    all_tests_passed &= TestInputValidation();
    PrintTestResult("Input Validation", all_tests_passed);
    
    all_tests_passed &= TestEncryptionDecryption();
    PrintTestResult("Encryption/Decryption", all_tests_passed);
    
    all_tests_passed &= TestRoundTripEncryption();
    PrintTestResult("Round-Trip Encryption", all_tests_passed);
    
    all_tests_passed &= TestFixedLenByteArrayValidation();
    PrintTestResult("FIXED_LEN_BYTE_ARRAY Validation", all_tests_passed);
    
    all_tests_passed &= TestResultStorage();
    PrintTestResult("Result Storage", all_tests_passed);
    
    all_tests_passed &= TestConvertEncodingAttributesToValuesComplete();
    PrintTestResult("ConvertEncodingAttributesToValues (Positive)", all_tests_passed);
    
    all_tests_passed &= TestConvertEncodingAttributesToValuesInvalid();
    PrintTestResult("ConvertEncodingAttributesToValues (Negative)", all_tests_passed);
    
    std::cout << "=============================================" << std::endl;
    if (all_tests_passed) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests failed!" << std::endl;
        return 1;
    }
}
