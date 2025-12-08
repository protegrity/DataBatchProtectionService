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
#include "enum_utils.h"
#include "parquet_utils.h"
#include "../common/bytes_utils.h"
#include "compression_utils.h"
#include "../common/exceptions.h"
#include "encryptors/basic_encryptor.h"
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <optional>
#include <cassert>
#include <cstring>
#include <memory>

using namespace dbps::external;
using namespace dbps::enum_utils;
using namespace dbps::compression;

namespace {
    constexpr const char* DBPS_VERSION_KEY = "dbps_agent_version";
    constexpr const char* DBPS_VERSION = "v0.01";
    constexpr const char* ENCRYPTION_MODE = "encryption_mode";
    constexpr const char* ENCRYPTION_PER_BLOCK = "per_block";
    constexpr const char* ENCRYPTION_PER_VALUE = "per_value";
}

// Helper function to create encryptor instance
static std::unique_ptr<DBPSEncryptor> CreateEncryptor(
    const std::string& key_id,
    const std::string& column_name,
    const std::string& user_id,
    const std::string& application_context,
    Type::type datatype) {

    // Return a BasicEncryptor instance.
    return std::make_unique<BasicEncryptor>(key_id, column_name, user_id, application_context, datatype);
}

// Constructor implementation
DataBatchEncryptionSequencer::DataBatchEncryptionSequencer(
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
) : column_name_(column_name),
    datatype_(datatype),
    datatype_length_(datatype_length),
    compression_(compression),
    format_(format),
    encoding_attributes_(encoding_attributes),
    encrypted_compression_(encrypted_compression),
    key_id_(key_id),
    user_id_(user_id),
    application_context_(application_context),
    encryption_metadata_(encryption_metadata),
    encryptor_(CreateEncryptor(key_id, column_name, user_id, application_context, datatype)) {}

// Constructor with pre-built encryptor
DataBatchEncryptionSequencer::DataBatchEncryptionSequencer(
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
) : column_name_(column_name),
    datatype_(datatype),
    datatype_length_(datatype_length),
    compression_(compression),
    format_(format),
    encoding_attributes_(encoding_attributes),
    encrypted_compression_(encrypted_compression),
    key_id_(key_id),
    user_id_(user_id),
    application_context_(application_context),
    encryption_metadata_(encryption_metadata),
    encryptor_(std::move(encryptor)) {}

// Top level encryption/decryption methods.

// TODO: Rename this method so it captures better the flow of decompress/format and encrypt/decrypt operations.
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

    try {
        // Decompress and split plaintext into level and value bytes
        auto [level_bytes, value_bytes] = DecompressAndSplit(
            plaintext, compression_, encoding_attributes_converted_);
        
        // Parse value bytes into typed list
        auto typed_list = ParseValueBytesIntoTypedList(value_bytes, datatype_, datatype_length_, format_);
        
        // Encrypt the typed list and level bytes, then join them into a single encrypted byte vector.
        auto encrypted_value_bytes = encryptor_->EncryptValueList(typed_list);
        auto encrypted_level_bytes = encryptor_->EncryptBlock(level_bytes);
        auto joined_encrypted_bytes = JoinWithLengthPrefix(encrypted_level_bytes, encrypted_value_bytes);
        
        // Compress the joined encrypted bytes
        encrypted_result_ = Compress(joined_encrypted_bytes, encrypted_compression_);

    }
    // If the sequence was interrupted by a DBPSUnsupportedException, allow fallback to per-block encryption
    // but only for explicitly unsupported conditions.
    // Any conditions that are already supported should not fallback. In those cases, the exception is re-thrown.
    catch (const DBPSUnsupportedException& e) {

        // Compression: Only UNCOMPRESSED and SNAPPY are supported
        const bool is_compression_supported = (compression_ == CompressionCodec::UNCOMPRESSED ||
                                               compression_ == CompressionCodec::SNAPPY);
        
        // Format: Only PLAIN is supported
        const bool is_format_supported = (format_ == Format::PLAIN);
        
        // Page type: All are supported (DATA_PAGE_V1, DATA_PAGE_V2, DICTIONARY_PAGE)
        const bool is_page_supported = true;
        
        // Datatype: All datatypes are supported.
        const bool is_datatype_supported = true;

        if (is_compression_supported && is_format_supported && is_page_supported && is_datatype_supported) {
            // All conditions are supported, therefore an DBPSUnsupportedException exception should not have happened. 
            // Re-throw the exception.
            throw;
        }

        // Fallback: Use per-block encryption for unsupported combinations.
        encrypted_result_ = encryptor_->EncryptBlock(plaintext);
        if (encrypted_result_.empty()) {
            error_stage_ = "encryption";
            error_message_ = "Failed to encrypt data";
            return false;
        }
        encryption_metadata_[ENCRYPTION_MODE] = ENCRYPTION_PER_BLOCK;
        encryption_metadata_[DBPS_VERSION_KEY] = DBPS_VERSION;
        return true;

    } catch (const InvalidInputException& e) {
        // Throw the exception so it can be caught by the caller.
        throw;
    }

    // If the sequencer got here, it means the encryption of the values in the typed list finished successfully.
    // Set the encryption type to per value
    encryption_metadata_[ENCRYPTION_MODE] = ENCRYPTION_PER_VALUE;
    encryption_metadata_[DBPS_VERSION_KEY] = DBPS_VERSION;
    return true;
}

// TODO: Rename this method so it captures better the flow of decompress/format and encrypt/decrypt operations.
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
    
    // Check encryption_metadata for dbps_agent_version
    std::string version_error = ValidateDecryptionVersion();
    if (!version_error.empty()) {
        error_stage_ = "decrypt_version_check";
        error_message_ = version_error;
        return false;
    }
    
    // Get encryption_mode from encryption_metadata
    auto encryption_mode_opt = SafeGetEncryptionMode();
    if (!encryption_mode_opt.has_value()) {
        error_stage_ = "decrypt_encryption_mode_validation";
        error_message_ = "Failed to get encryption_mode from encryption_metadata";
        return false;
    }
    std::string encryption_mode = encryption_mode_opt.value();
    
    // Per-value encryption
    if (encryption_mode == ENCRYPTION_PER_VALUE) {
        // Decompress the encrypted bytes
        auto decompressed_encrypted_bytes = Decompress(ciphertext, encrypted_compression_);
        
        // Split the joined encrypted bytes, then decrypt the level and value bytes separately.
        auto [encrypted_level_bytes, encrypted_value_bytes] = SplitWithLengthPrefix(decompressed_encrypted_bytes);
        auto level_bytes = encryptor_->DecryptBlock(encrypted_level_bytes);
        auto typed_list = encryptor_->DecryptValueList(encrypted_value_bytes);
        
        // Convert the decrypted typed list back to value bytes
        auto value_bytes = GetTypedListAsValueBytes(typed_list, datatype_, datatype_length_, format_);
        
        // Join the decrypted level and value bytes, then compress to get plaintext
        decrypted_result_ = CompressAndJoin(
            level_bytes, value_bytes, compression_, encoding_attributes_converted_);
    }
    
    // Per-block encryption
    else if (encryption_mode == ENCRYPTION_PER_BLOCK) {
        // Simple XOR decryption (same operation as encryption) for per-block encryption
        decrypted_result_ = encryptor_->DecryptBlock(ciphertext);
        if (decrypted_result_.empty()) {
            error_stage_ = "decryption";
            error_message_ = "Failed to decrypt data";
            return false;
        }
    }
    
    return true;
}

// Helper methods to validate and basic parameter reading.

bool DataBatchEncryptionSequencer::ConvertEncodingAttributesToValues() {
    try {
        auto add_str = [&](const std::string& key) {
            return AddStringAttribute(encoding_attributes_converted_, encoding_attributes_, key);
        };
        auto add_int = [&](const std::string& key) {
            return AddIntAttribute(encoding_attributes_converted_, encoding_attributes_, key);
        };
        auto add_bool = [&](const std::string& key) {
            return AddBoolAttribute(encoding_attributes_converted_, encoding_attributes_, key);
        };

        std::string page_type = add_str("page_type");
        // Convert common attributes for DATA_PAGE_V1 and DATA_PAGE_V2
        if (page_type == "DATA_PAGE_V1" || page_type == "DATA_PAGE_V2") {
            add_int("data_page_num_values");
            add_int("data_page_max_definition_level");
            add_int("data_page_max_repetition_level");
        }
        if (page_type == "DATA_PAGE_V1") {
            add_str("page_v1_definition_level_encoding");
            add_str("page_v1_repetition_level_encoding");
            
        } else if (page_type == "DATA_PAGE_V2") {
            add_int("page_v2_definition_levels_byte_length");
            add_int("page_v2_repetition_levels_byte_length");
            add_int("page_v2_num_nulls");
            add_bool("page_v2_is_compressed");
        } else if (page_type == "DICTIONARY_PAGE") {
            // DICTIONARY_PAGE has no specific encoding attributes
        }
        return true;
        
    } catch (const InvalidInputException& e) {
        error_stage_ = "encoding_attribute_conversion";
        error_message_ = e.what();
        return false;
    }
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

std::string DataBatchEncryptionSequencer::ValidateDecryptionVersion() {
    auto it = encryption_metadata_.find(DBPS_VERSION_KEY);
    if (it == encryption_metadata_.end()) {
        std::cerr << "ERROR: EncryptionSequencer - encryption_metadata must contain key '" << DBPS_VERSION_KEY << "'" << std::endl;
        return "encryption_metadata must contain key '" + std::string(DBPS_VERSION_KEY) + "'";
    } else if (it->second.find(DBPS_VERSION) != 0) {
        std::cerr << "ERROR: EncryptionSequencer - encryption_metadata['" << DBPS_VERSION_KEY << "'] must match '" 
                  << DBPS_VERSION << "', but got '" << it->second << "'" << std::endl;
        return "encryption_metadata['" + std::string(DBPS_VERSION_KEY) + "'] must match '" + std::string(DBPS_VERSION) + "'";
    }
    return "";
}

std::optional<std::string> DataBatchEncryptionSequencer::SafeGetEncryptionMode() {
    auto it = encryption_metadata_.find(ENCRYPTION_MODE);
    if (it == encryption_metadata_.end()) {
        // The metadata key for encryption mode is missing.
        return std::nullopt;
    }
    const std::string& encryption_mode = it->second;
    if (encryption_mode != ENCRYPTION_PER_BLOCK && encryption_mode != ENCRYPTION_PER_VALUE) {
        // The value for encryption mode is not valid.
        return std::nullopt;
    }
    return encryption_mode;
}
