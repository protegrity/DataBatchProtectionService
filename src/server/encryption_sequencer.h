#pragma once

#include <string>
#include <vector>
#include "enums.h"

/**
 * Encryption sequencer class that handles data conversion and encryption/decryption operations.
 * 
 * Features:
 * - Validates and converts string parameters to enum values
 * - Supports base64 decoding of input data
 * - Implements simple XOR-based encryption/decryption using key_id
 * - Validates supported parameter combinations (uncompressed, base64, raw_c_data)
 * - Provides comprehensive error reporting with stage and message tracking
 * 
 * Currently supports only:
 * - Compression: UNCOMPRESSED
 * - Encoding: BASE64  
 * - Format: RAW_C_DATA
 * 
 * The class takes constructor parameters that were previously public attributes in JsonRequest.
 */
class DataBatchEncryptionSequencer {
public:
    std::string datatype_;
    std::string compression_;
    std::string format_;
    std::string encoding_;
    std::string encrypted_compression_;
    std::string key_id_;
    
    // Error reporting fields
    std::string error_stage_;
    std::string error_message_;
    
    // Constructor - simple setter of parameters
    DataBatchEncryptionSequencer(
        const std::string& datatype,
        const std::string& compression,
        const std::string& format,
        const std::string& encoding,
        const std::string& encrypted_compression,
        const std::string& key_id
    );
    
    // Default constructor
    DataBatchEncryptionSequencer() = default;
    
    // Destructor
    ~DataBatchEncryptionSequencer() = default;
    
    // Main processing methods
    bool ConvertAndEncrypt(const std::string& plaintext);
    bool ConvertAndDecrypt(const std::string& ciphertext);

private:
    // Corresponding enum values for the string parameters
    dbps::external::Type::type datatype_enum_;
    dbps::external::CompressionCodec::type compression_enum_;
    dbps::external::CompressionCodec::type encrypted_compression_enum_;
    dbps::external::Format::type format_enum_;
    dbps::external::Encoding::type encoding_enum_;

    /**
     * Converts string values to corresponding enum values using enum_utils.
     * Returns true if all conversions are successful, false otherwise.
     * Sets error_stage_ and error_message_ if conversion fails.
     */
    bool ConvertStringsToEnums();
    
    /**
     * Performs comprehensive validation of all parameters and key_id.
     * Converts string parameters to enums, validates key_id, and checks supported combinations.
     * Currently only supports: uncompressed, encoding=base64, format=raw_c_data
     * Returns true if all validation passes, false otherwise.
     */
    bool ValidateParameters();
    
    // Decode base64 string to binary data using cppcodec library
    std::vector<uint8_t> DecodeBase64(const std::string& base64_string);
    
    // Simple encryption/decryption using XOR with key_id hash
    std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecryptData(const std::vector<uint8_t>& data);
    
};
