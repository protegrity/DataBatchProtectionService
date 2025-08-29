#include "encryption_sequencer.h"
#include "enum_utils.h"
#include "decoding_utils.h"
#include <cppcodec/base64_rfc4648.hpp>
#include <functional>
#include <iostream>

// Constructor implementation
DataBatchEncryptionSequencer::DataBatchEncryptionSequencer(
    const std::string& datatype,
    const std::string& compression,
    const std::string& format,
    const std::string& encoding,
    const std::string& encrypted_compression,
    const std::string& key_id
) : datatype_(datatype),
    compression_(compression),
    format_(format),
    encoding_(encoding),
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
    
    // Debug: Print the decoded plaintext data (only for uncompressed data)
    if (compression_enum_ == dbps::external::CompressionCodec::UNCOMPRESSED) {
        std::string debug_decoded = PrintPlainDecoded(decoded_data, datatype_enum_);
        std::cout << "Debug - Decoded plaintext data:\n" << debug_decoded << std::endl;
    } else {
        std::cout << "Debug - Data is compressed (" << compression_ << "), skipping detailed decode output. Raw size: " 
                  << decoded_data.size() << " bytes" << std::endl;
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
    
    // Convert encoding string to enum
    auto encoding_result = dbps::enum_utils::to_encoding_enum(encoding_);
    if (!encoding_result) {
        error_stage_ = "encoding_conversion";
        error_message_ = "Invalid encoding: " + encoding_;
        return false;
    }
    encoding_enum_ = *encoding_result;
    
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
    
    // Check compression: warn if not UNCOMPRESSED but continue
    if (CHECK_COMPRESSION_ENUM && compression_enum_ != dbps::external::CompressionCodec::UNCOMPRESSED) {
        std::cerr << "WARNING: Non-UNCOMPRESSED compression requested: " << compression_ 
                  << ". Only UNCOMPRESSED is currently implemented, proceeding anyway." << std::endl;
    }
    
    // Check encrypted_compression: warn if not UNCOMPRESSED but continue
    if (CHECK_COMPRESSION_ENUM && encrypted_compression_enum_ != dbps::external::CompressionCodec::UNCOMPRESSED) {
        std::cerr << "WARNING: Non-UNCOMPRESSED encrypted_compression requested: " << encrypted_compression_ 
                  << ". Only UNCOMPRESSED is currently implemented, proceeding anyway." << std::endl;
    }
    
    // Check encoding: must be BASE64
    if (encoding_enum_ != dbps::external::Encoding::BASE64) {
        error_stage_ = "parameter_validation";
        error_message_ = "Only BASE64 encoding is supported";
        return false;
    }
    
    // Check format: must be RAW_C_DATA
    if (format_enum_ != dbps::external::Format::RAW_C_DATA) {
        error_stage_ = "parameter_validation";
        error_message_ = "Only RAW_C_DATA format is supported";
        return false;
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

    if (USE_SIMPLE_XOR_ENCRYPTION) {
        for (size_t i = 0; i < data.size(); ++i) {
            encrypted_data[i] = data[i] ^ 0xAA;
        }
    }
    else {
        // Generate a simple key from key_id by hashing it
        std::hash<std::string> hasher;
        size_t key_hash = hasher(key_id_);
        
        // XOR each byte with the key hash
        for (size_t i = 0; i < data.size(); ++i) {
            encrypted_data[i] = data[i] ^ (key_hash & 0xFF);
            // Rotate the key hash for next byte
            key_hash = (key_hash << 1) | (key_hash >> 31);
        }
    }    
    return encrypted_data;
}

std::vector<uint8_t> DataBatchEncryptionSequencer::DecryptData(const std::vector<uint8_t>& data) {
    // For XOR encryption, decryption is the same as encryption
    return EncryptData(data);
}
