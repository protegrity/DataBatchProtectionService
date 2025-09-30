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
    std::string datatype_;
    std::optional<int> datatype_length_;
    std::string compression_;
    std::string format_;
    std::map<std::string, std::string> encoding_attributes_;
    std::string encrypted_compression_;
    std::string key_id_;
    
    // Error reporting fields
    std::string error_stage_;
    std::string error_message_;
    
    // Result storage
    std::string encrypted_result_;
    std::string decrypted_result_;
    
    // Constructor - simple setter of parameters
    DataBatchEncryptionSequencer(
        const std::string& datatype,
        const std::optional<int>& datatype_length,
        const std::string& compression,
        const std::string& format,
        const std::map<std::string, std::string>& encoding_attributes,
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
    Type::type datatype_enum_;
    CompressionCodec::type compression_enum_;
    CompressionCodec::type encrypted_compression_enum_;
    Format::type format_enum_;
    
    // Converted encoding attributes values to corresponding types
    std::map<std::string, std::variant<int, bool, std::string>> encoding_attributes_converted_;
    
    /**
     * Converts string values to corresponding enum values using enum_utils.
     * Returns true if all conversions are successful, false otherwise.
     * Sets error_stage_ and error_message_ if conversion fails.
     */
    bool ConvertStringsToEnums();
    
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
