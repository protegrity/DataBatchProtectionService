#pragma once

#include <string>
#include <vector>
#include <optional>
#include <variant>
#include <map>
#include "enums.h"

using namespace dbps::external;

/**
 * Encryption sequencer class that handles data conversion and encryption/decryption operations.
 * 
 * Features:
 * - Validates and converts string parameters to enum values
 * - Supports base64 decoding of input data
 * - Implements simple XOR-based encryption/decryption using key_id
 * - Validates supported parameter combinations (uncompressed, base64, plain)
 * - Provides comprehensive error reporting with stage and message tracking
 * 
 * Supports all data types, compression types, and formats.
 * 
 * The class takes constructor parameters that were previously public attributes in JsonRequest.
 */
class DataBatchEncryptionSequencer {
public:
    // TODO: Move these to protected attributes if no external access is needed.
    Type::type datatype_;
    std::optional<int> datatype_length_;
    CompressionCodec::type compression_;
    Format::type format_;
    std::map<std::string, std::string> encoding_attributes_;
    CompressionCodec::type encrypted_compression_;
    std::string key_id_;
    
    // Error reporting fields
    std::string error_stage_;
    std::string error_message_;
    
    // Result storage
    std::string encrypted_result_;
    std::string decrypted_result_;
    
    // Constructor - simple setter of parameters
    DataBatchEncryptionSequencer(
        Type::type datatype,
        const std::optional<int>& datatype_length,
        CompressionCodec::type compression,
        Format::type format,
        const std::map<std::string, std::string>& encoding_attributes,
        CompressionCodec::type encrypted_compression,
        const std::string& key_id
    );
    
    // Default constructor
    DataBatchEncryptionSequencer() = default;
    
    // Destructor
    ~DataBatchEncryptionSequencer() = default;
    
    // Main processing methods
    bool ConvertAndEncrypt(const std::string& plaintext);
    bool ConvertAndDecrypt(const std::string& ciphertext);

protected:
    // Converted encoding attributes values to corresponding types
    std::map<std::string, std::variant<int32_t, bool, std::string>> encoding_attributes_converted_;
    
    /**
     * Converts encoding attributes string values to corresponding typed values.
     * Reads specific keys from encoding_attributes_ corresponding to Parquet encoding attributes.
     * Returns true if all conversions are successful, false otherwise.
     * Sets error_stage_ and error_message_ if conversion fails.
     */
    bool ConvertEncodingAttributesToValues();
    
    /**
     * Performs comprehensive validation of all parameters and key_id.
     * Converts string parameters to enums, validates key_id, and checks supported combinations.
     * Supports all data types, compression types, and formats.
     * Returns true if all validation passes, false otherwise.
     */
    bool ValidateParameters();
    
    // Encode-decode base64 string to binary data using cppcodec library
    std::vector<uint8_t> DecodeBase64(const std::string& base64_string);
    std::string EncodeBase64(const std::vector<uint8_t>& data);
    
    // Simple encryption/decryption using XOR with key_id hash
    std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecryptData(const std::vector<uint8_t>& data);
    
};
