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

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "enums.h"
#include "decoding_utils.h"
#include "encryptors/dbps_encryptor.h"
#include <memory>

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

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
    
    // Constructor with pre-built encryptor (for dependency injection)
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
        const std::map<std::string, std::string>& encryption_metadata,
        std::unique_ptr<DBPSEncryptor> encryptor
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
    
    // Encryptor instance for performing encryption/decryption operations
    std::unique_ptr<DBPSEncryptor> encryptor_;

    /**
     * Decompresses and splits the plaintext into level and value bytes.
     * Returns the level and value bytes.
     */
     LevelAndValueBytes DecompressAndSplit(const std::vector<uint8_t>& plaintext);

     /**
      * Merges level and value bytes and compresses them into plaintext.
      * This is the reverse operation of DecompressAndSplit.
      * Handles different page types (DATA_PAGE_V1, DATA_PAGE_V2, DICTIONARY_PAGE) appropriately.
      * Returns the joined and compressed plaintext.
      */
     std::vector<uint8_t> CompressAndJoin(const std::vector<uint8_t>& level_bytes, const std::vector<uint8_t>& value_bytes);
 

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
     * Validates the DBPS version in encryption_metadata during decryption.
     * The DBPS server version check during Decrypt is to future-proof against changes on the Encryption process.
     * The Encryption process could change due to updates on the payload decoding, updates on fallback encryption methods, or other changes,
     * and it is possible that it results on a mismatch with the Decryption implementation. This check helps to catch such mismatches.
     * Returns empty string if validation passes, otherwise returns the error message.
     */
     std::string ValidateDecryptionVersion();
    
    /**
     * Safely gets the encryption_mode value from encryption_metadata.
     * Returns the encryption mode value ("per_block" or "per_value") if found and valid,
     * otherwise returns empty string.
     */
    std::optional<std::string> SafeGetEncryptionMode();
    
};
