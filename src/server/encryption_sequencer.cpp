#include "encryption_sequencer.h"
#include "enum_utils.h"
#include "decoding_utils.h"
#include <functional>
#include <iostream>
#include <sstream>
#include <optional>
#include <cassert>

using namespace dbps::external;
using namespace dbps::enum_utils;

// Constructor implementation
DataBatchEncryptionSequencer::DataBatchEncryptionSequencer(
    Type::type datatype,
    const std::optional<int>& datatype_length,
    CompressionCodec::type compression,
    Format::type format,
    const std::map<std::string, std::string>& encoding_attributes,
    CompressionCodec::type encrypted_compression,
    const std::string& key_id
) : datatype_(datatype),
    datatype_length_(datatype_length),
    compression_(compression),
    format_(format),
    encoding_attributes_(encoding_attributes),
    encrypted_compression_(encrypted_compression),
    key_id_(key_id) {}

// Main processing methods
bool DataBatchEncryptionSequencer::ConvertAndEncrypt(const std::vector<uint8_t>& plaintext) {
    // Validate all parameters and key_id
    if (!ValidateParameters()) {
        return false;
    }
    
    // Check that plaintext is not null and not empty
    if (plaintext.empty()) {
        error_stage_ = "validation";
        error_message_ = "plaintext cannot be null or empty";
        return false;
    }
    
    // The plaintext is in binary format, so we can use it directly
    const std::vector<uint8_t>& decoded_data = plaintext;
    
    // Integration point for data element based encryptors.
    // - Currently, the function simply prints the decoded plaintext data (for uncompressed data and PLAIN format)
    // - However, a full pledged "data element" encryptor can hook to this method and instead of printing the decoded data,
    //   it can encrypt the data element itself, replacing the naive XOR encryption step below.
    bool is_compressed = compression_ != CompressionCodec::UNCOMPRESSED;
    bool is_plain = format_ == Format::PLAIN;
    if (is_compressed) {
        std::cout << "Encrypt value - Data is compressed (" << to_string(compression_) << "), skipping detailed decode output. Raw size: " 
                  << decoded_data.size() << " bytes" << std::endl;
    }
    if (!is_plain) {
        std::cout << "Encrypt value - Data format is not PLAIN (" << to_string(format_) << "), skipping detailed decode output. Raw size: " 
                  << decoded_data.size() << " bytes" << std::endl;
    }    
    if (!is_compressed && is_plain) {
        // Calculate the number of leading bytes to strip based on the encoding attributes
        int leading_bytes_to_strip = CalculateLevelBytesLength(decoded_data, encoding_attributes_converted_);

        // Only show detailed decode output if both UNCOMPRESSED and PLAIN
        std::string debug_decoded = PrintPlainDecoded(decoded_data, datatype_, datatype_length_, leading_bytes_to_strip);
        if (debug_decoded.length() > 1000) {
            std::cout << "Encrypt value - Decoded plaintext data (first 1000 chars):\n" 
                      << debug_decoded.substr(0, 1000) << "..." << std::endl;
        } else {
            std::cout << "Encrypt value - Decoded plaintext data:\n" << debug_decoded << std::endl;
        }
    }
    
    // Simple XOR encryption
    encrypted_result_ = EncryptData(decoded_data);
    if (encrypted_result_.empty()) {
        error_stage_ = "encryption";
        error_message_ = "Failed to encrypt data";
        return false;
    }
    
    return true;
}

bool DataBatchEncryptionSequencer::ConvertAndDecrypt(const std::vector<uint8_t>& ciphertext) {
    // Validate all parameters and key_id
    if (!ValidateParameters()) {
        return false;
    }
    
    // Check that ciphertext is not null and not empty
    if (ciphertext.empty()) {
        error_stage_ = "validation";
        error_message_ = "ciphertext cannot be null or empty";
        return false;
    }
    
    // The ciphertext is in binary format, so we can use it directly
    const std::vector<uint8_t>& encrypted_data = ciphertext;
    
    // Simple XOR decryption (same operation as encryption)
    decrypted_result_ = DecryptData(encrypted_data);
    if (decrypted_result_.empty()) {
        error_stage_ = "decryption";
        error_message_ = "Failed to decrypt data";
        return false;
    }
    
    return true;
}

bool DataBatchEncryptionSequencer::ConvertEncodingAttributesToValues() {
    // Helper to find key and return value or null
    auto FindKey = [this](const std::string& key) -> const std::string* {
        auto it = encoding_attributes_.find(key);
        if (it == encoding_attributes_.end()) {
            error_stage_ = "encoding_attribute_validation";
            error_message_ = "Required encoding attribute [" + key + "] is missing";
            return nullptr;
        }
        return &it->second;
    };
    
    // Type-specific conversion helpers
    auto SafeAddIntToMap = [this, &FindKey](const std::string& key) -> bool {
        const std::string* value = FindKey(key);
        if (!value) {
            return false;
        }
        try {
            int32_t value_int = static_cast<int32_t>(std::stol(*value));
            encoding_attributes_converted_[key] = value_int;
            assert(value_int >= 0);
            return true;
        } catch (const std::exception& e) {
            error_stage_ = "encoding_attribute_conversion";
            error_message_ = "Failed to convert [" + key + "] with value [" + *value + "] to int: " + e.what();
            return false;
        }
    };
    
    auto SafeAddBoolToMap = [this, &FindKey](const std::string& key) -> bool {
        const std::string* value = FindKey(key);
        if (!value) {
            return false;
        }
        if (*value == "true") {
            encoding_attributes_converted_[key] = true;
            return true;
        } else if (*value == "false") {
            encoding_attributes_converted_[key] = false;
            return true;
        } else {
            error_stage_ = "encoding_attribute_conversion";
            error_message_ = "Failed to convert [" + key + "] with value [" + *value + "] to bool";
            return false;
        }
    };
    
    auto SafeAddStringToMap = [this, &FindKey](const std::string& key) -> bool {
        const std::string* value = FindKey(key);
        if (!value) {
            return false;
        }
        encoding_attributes_converted_[key] = *value;
        return true;
    };
    
    if (!SafeAddStringToMap("page_type")) return false;
    std::string page_type = encoding_attributes_["page_type"];
    
    // Convert common attributes for DATA_PAGE_V1 and DATA_PAGE_V2
    if (page_type == "DATA_PAGE_V1" || page_type == "DATA_PAGE_V2") {
        if (!SafeAddIntToMap("data_page_num_values")) return false;
        if (!SafeAddIntToMap("data_page_max_definition_level")) return false;
        if (!SafeAddIntToMap("data_page_max_repetition_level")) return false;
    }
    if (page_type == "DATA_PAGE_V1") {
        if (!SafeAddStringToMap("page_v1_definition_level_encoding")) return false;
        if (!SafeAddStringToMap("page_v1_repetition_level_encoding")) return false;
        
    } else if (page_type == "DATA_PAGE_V2") {
        if (!SafeAddIntToMap("page_v2_definition_levels_byte_length")) return false;
        if (!SafeAddIntToMap("page_v2_repetition_levels_byte_length")) return false;
        if (!SafeAddIntToMap("page_v2_num_nulls")) return false;
        if (!SafeAddBoolToMap("page_v2_is_compressed")) return false;
    } else if (page_type == "DICTIONARY_PAGE") {
        // DICTIONARY_PAGE has no specific encoding attributes
    }
    
    return true;
}

bool DataBatchEncryptionSequencer::ValidateParameters() {
    // Convert encoding attributes to typed values
    if (!ConvertEncodingAttributesToValues()) {
        return false;
    }
    
    // Check that key_id is not null and not empty
    if (key_id_.empty()) {
        error_stage_ = "validation";
        error_message_ = "key_id cannot be null or empty";
        return false;
    }

    // Check FIXED_LEN_BYTE_ARRAY datatype_length requirement
    if (datatype_ == Type::FIXED_LEN_BYTE_ARRAY) {
        if (!datatype_length_.has_value()) {
            error_stage_ = "parameter_validation";
            error_message_ = "FIXED_LEN_BYTE_ARRAY datatype requires datatype_length parameter";
            return false;
        }
        if (datatype_length_.value() <= 0) {
            error_stage_ = "parameter_validation";
            error_message_ = "FIXED_LEN_BYTE_ARRAY datatype_length must be positive";
            return false;
        }
    }
    
    return true;
}

std::vector<uint8_t> DataBatchEncryptionSequencer::EncryptData(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::vector<uint8_t>();
    }
    
    std::vector<uint8_t> encrypted_data(data.size());

    // Generate a simple key from key_id by hashing it
    std::hash<std::string> hasher;
    size_t key_hash = hasher(key_id_);
    
    // XOR each byte with the key hash
    for (size_t i = 0; i < data.size(); ++i) {
        encrypted_data[i] = data[i] ^ (key_hash & 0xFF);
        // Rotate the key hash for next byte
        key_hash = (key_hash << 1) | (key_hash >> 31);
    }

    return encrypted_data;
}

std::vector<uint8_t> DataBatchEncryptionSequencer::DecryptData(const std::vector<uint8_t>& data) {
    // For XOR encryption, decryption is the same as encryption
    return EncryptData(data);
}
