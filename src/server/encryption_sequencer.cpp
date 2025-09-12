#include "encryption_sequencer.h"
#include "enum_utils.h"
#include "decoding_utils.h"
#include <cppcodec/base64_rfc4648.hpp>
#include <functional>
#include <iostream>

using namespace dbps::external;

// Constructor implementation
DataBatchEncryptionSequencer::DataBatchEncryptionSequencer(
    const std::string& datatype,
    const std::optional<int>& datatype_length,
    const std::string& compression,
    const std::string& format,
    const std::string& encrypted_compression,
    const std::string& key_id
) : datatype_(datatype),
    datatype_length_(datatype_length),
    compression_(compression),
    format_(format),
    encrypted_compression_(encrypted_compression),
    key_id_(key_id) {}

// Main processing methods
bool DataBatchEncryptionSequencer::ConvertAndEncrypt(const std::string& plaintext) {
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
    
    // Decode the base64 plaintext to get the original binary data
    std::vector<uint8_t> decoded_data = DecodeBase64(plaintext);
    if (decoded_data.empty()) {
        error_stage_ = "base64_decoding";
        error_message_ = "Failed to decode base64 plaintext";
        return false;
    }
    
    // Integration point for data element based encryptors.
    // - Currently, the function simply prints the decoded plaintext data (for uncompressed data and PLAIN format)
    // - However, a full pledged "data element" encryptor can hook to this method and instead of printing the decoded data,
    //   it can encrypt the data element itself, replacing the naive XOR encryption step below.
    bool is_uncompressed = compression_enum_ == CompressionCodec::UNCOMPRESSED;
    bool is_plain = format_enum_ == Format::PLAIN;
    if (!is_uncompressed) {
        std::cout << "Encrypt value - Data is compressed (" << compression_ << "), skipping detailed decode output. Raw size: " 
                  << decoded_data.size() << " bytes" << std::endl;
    }
    if (!is_plain) {
        std::cout << "Encrypt value - Data format is not PLAIN (" << format_ << "), skipping detailed decode output. Raw size: " 
                  << decoded_data.size() << " bytes" << std::endl;
    }    
    if (is_uncompressed && is_plain) {
        // Only show detailed decode output if both UNCOMPRESSED and PLAIN
        std::string debug_decoded = PrintPlainDecoded(decoded_data, datatype_enum_, datatype_length_);
        if (debug_decoded.length() > 1000) {
            std::cout << "Encrypt value - Decoded plaintext data (first 1000 chars):\n" 
                      << debug_decoded.substr(0, 1000) << "..." << std::endl;
        } else {
            std::cout << "Encrypt value - Decoded plaintext data:\n" << debug_decoded << std::endl;
        }
    }
    
    // Simple XOR encryption
    std::vector<uint8_t> encrypted_data = EncryptData(decoded_data);
    if (encrypted_data.empty()) {
        error_stage_ = "encryption";
        error_message_ = "Failed to encrypt data";
        return false;
    }
    
    // Encode encrypted data back to base64
    encrypted_result_ = EncodeBase64(encrypted_data);
    if (encrypted_result_.empty()) {
        error_stage_ = "base64_encoding";
        error_message_ = "Failed to encode encrypted data to base64";
        return false;
    }
    
    return true;
}

bool DataBatchEncryptionSequencer::ConvertAndDecrypt(const std::string& ciphertext) {
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
    
    // Decode the base64 ciphertext to get the encrypted binary data
    std::vector<uint8_t> encrypted_data = DecodeBase64(ciphertext);
    if (encrypted_data.empty()) {
        error_stage_ = "base64_decoding";
        error_message_ = "Failed to decode base64 ciphertext";
        return false;
    }
    
    // Simple XOR decryption (same operation as encryption)
    std::vector<uint8_t> decrypted_data = DecryptData(encrypted_data);
    if (decrypted_data.empty()) {
        error_stage_ = "decryption";
        error_message_ = "Failed to decrypt data";
        return false;
    }
    
    // Encode decrypted data back to base64
    decrypted_result_ = EncodeBase64(decrypted_data);
    if (decrypted_result_.empty()) {
        error_stage_ = "base64_encoding";
        error_message_ = "Failed to encode decrypted data to base64";
        return false;
    }
    
    return true;
}

bool DataBatchEncryptionSequencer::ConvertStringsToEnums() {
    // Convert datatype string to enum
    auto datatype_result = dbps::enum_utils::to_datatype_enum(datatype_);
    if (!datatype_result) {
        error_stage_ = "datatype_conversion";
        error_message_ = "Invalid datatype: " + datatype_;
        return false;
    }
    datatype_enum_ = *datatype_result;
    
    // Convert compression string to enum
    auto compression_result = dbps::enum_utils::to_compression_enum(compression_);
    if (!compression_result) {
        error_stage_ = "compression_conversion";
        error_message_ = "Invalid compression: " + compression_;
        return false;
    }
    compression_enum_ = *compression_result;
    
    // Convert encrypted_compression string to enum (same as compression)
    auto encrypted_compression_result = dbps::enum_utils::to_compression_enum(encrypted_compression_);
    if (!encrypted_compression_result) {
        error_stage_ = "encrypted_compression_conversion";
        error_message_ = "Invalid encrypted_compression: " + encrypted_compression_;
        return false;
    }
    encrypted_compression_enum_ = *encrypted_compression_result;
    
    // Convert format string to enum
    auto format_result = dbps::enum_utils::to_format_enum(format_);
    if (!format_result) {
        error_stage_ = "format_conversion";
        error_message_ = "Invalid format: " + format_;
        return false;
    }
    format_enum_ = *format_result;
    
    return true;
}

bool DataBatchEncryptionSequencer::ValidateParameters() {
    // First check: convert string values to enums
    if (!ConvertStringsToEnums()) {
        return false;
    }
    
    // Check that key_id is not null and not empty
    if (key_id_.empty()) {
        error_stage_ = "validation";
        error_message_ = "key_id cannot be null or empty";
        return false;
    }

    // Check FIXED_LEN_BYTE_ARRAY datatype_length requirement
    if (datatype_enum_ == Type::FIXED_LEN_BYTE_ARRAY) {
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

std::vector<uint8_t> DataBatchEncryptionSequencer::DecodeBase64(const std::string& base64_string) {
    try {
        // Use cppcodec library for robust base64 decoding
        return cppcodec::base64_rfc4648::decode(base64_string);
    } catch (const std::exception& e) {
        // Return empty vector on any decoding error
        return std::vector<uint8_t>();
    }
}

std::string DataBatchEncryptionSequencer::EncodeBase64(const std::vector<uint8_t>& data) {
    try {
        // Use cppcodec library for robust base64 encoding
        return cppcodec::base64_rfc4648::encode(data);
    } catch (const std::exception& e) {
        // Return empty string on any encoding error
        return "";
    }
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
