#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "enums.h"

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

class DBPS_EXPORT DBPSUnsupportedException : public std::runtime_error {
public:
    explicit DBPSUnsupportedException(const std::string& message) : std::runtime_error(message) {}
};

class DBPS_EXPORT InvalidInputException : public std::runtime_error {
public:
    explicit InvalidInputException(const std::string& message) : std::runtime_error(message) {}
};

struct LevelAndValueBytes {
    std::vector<uint8_t> level_bytes;
    std::vector<uint8_t> value_bytes;
};

using TypedListValues = std::variant<
    std::vector<int32_t>,
    std::vector<int64_t>,
    std::vector<float>,
    std::vector<double>,
    std::vector<std::array<uint32_t, 3>>,     // For INT96
    std::vector<std::string>,                 // For BYTE_ARRAY and FIXED_LEN_BYTE_ARRAY
    std::vector<uint8_t>                      // For UNDEFINED
>;

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
    // Result storage
    std::vector<uint8_t> encrypted_result_;
    std::vector<uint8_t> decrypted_result_;

    // Encryption metadata
    std::map<std::string, std::string> encryption_metadata_;
    
    // Error reporting fields
    std::string error_stage_;
    std::string error_message_;
    
    // Constructor - simple setter of parameters
    DataBatchEncryptionSequencer(
        const std::string& column_name,
        Type::type datatype,
        const std::optional<int>& datatype_length,
        CompressionCodec::type compression,
        Format::type format,
        const std::map<std::string, std::string>& encoding_attributes,
        CompressionCodec::type encrypted_compression,
        const std::string& key_id,
        const std::string& user_id,
        const std::string& application_context,
        const std::map<std::string, std::string>& encryption_metadata
    );
    
    // Default constructor
    DataBatchEncryptionSequencer() = default;
    
    // Destructor
    ~DataBatchEncryptionSequencer() = default;
    
    // Main processing methods
    bool ConvertAndEncrypt(const std::vector<uint8_t>& plaintext);
    bool ConvertAndDecrypt(const std::vector<uint8_t>& ciphertext);

protected:
    // Parameters for encryption/decryption operations
    std::string column_name_;
    Type::type datatype_;
    std::optional<int> datatype_length_;
    CompressionCodec::type compression_;
    Format::type format_;
    std::map<std::string, std::string> encoding_attributes_;
    CompressionCodec::type encrypted_compression_;
    std::string key_id_;
    std::string user_id_;
    std::string application_context_;

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

    /**
     * Decompresses and splits the plaintext into level and value bytes.
     * Returns the level and value bytes.
     */
    LevelAndValueBytes DecompressAndSplit(const std::vector<uint8_t>& plaintext);

    /**
     * Compress bytes using the compression codec. 
     */
    std::vector<uint8_t> Compress(const std::vector<uint8_t>& bytes);
    
    /**
     * Decompress bytes using the compression codec.
     */
    std::vector<uint8_t> Decompress(const std::vector<uint8_t>& bytes);
    
    /**
     * Split the input bytes in two parts, determined by the given index.
     */
    LevelAndValueBytes Split(const std::vector<uint8_t>& bytes, int index);

    /**
     * Parse the value bytes into a typed list of the types defined above.
     */
    TypedListValues ParseValueBytesIntoTypedList(const std::vector<uint8_t>& bytes);

    /**
     * Data element encryption function that will be the integration point for Protegrity.
     * The level_bytes and the elements need to be encrypted and combined into a single encrypted
     * vector of bytes.
     */
    std::vector<uint8_t> EncryptTypedList(
        const TypedListValues& typed_list, const std::vector<uint8_t>& level_bytes);
    
    // Simple encryption/decryption using XOR with key_id hash
    std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecryptData(const std::vector<uint8_t>& data);
    
};
