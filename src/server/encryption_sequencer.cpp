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
#include "decoding_utils.h"
#include "compression_utils.h"
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <optional>
#include <cassert>
#include <cstring>

using namespace dbps::external;
using namespace dbps::enum_utils;

namespace {
    constexpr const char* DBPS_VERSION_KEY = "dbps_agent_version";
    constexpr const char* DBPS_VERSION_VALUE = "v0.01";
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
    encryption_metadata_(encryption_metadata) {}

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
        auto level_and_value_bytes = DecompressAndSplit(plaintext);
        auto typed_list = ParseValueBytesIntoTypedList(
            level_and_value_bytes.value_bytes, datatype_, datatype_length_, format_);
        auto encrypted_bytes = EncryptTypedList(typed_list, level_and_value_bytes.level_bytes);
        encrypted_result_ = Compress(encrypted_bytes, encrypted_compression_);
    } catch (const DBPSUnsupportedException& e) {
        // If any stage is as of yet unsupported, default to whole payload 
        // (as opposed to per-value) XOR encryption
        encrypted_result_ = EncryptData(plaintext);
        if (encrypted_result_.empty()) {
            error_stage_ = "encryption";
            error_message_ = "Failed to encrypt data";
            return false;
        }
        encryption_metadata_[DBPS_VERSION_KEY] = DBPS_VERSION_VALUE;
        return true;
    } catch (const InvalidInputException& e) {
        // Throw the exception so it can be caught by the caller.
        throw;
    }
    encryption_metadata_[DBPS_VERSION_KEY] = DBPS_VERSION_VALUE;
    return true;
}

// Main processing methods

LevelAndValueBytes DataBatchEncryptionSequencer::DecompressAndSplit(
    const std::vector<uint8_t>& plaintext) {
    LevelAndValueBytes result;

    std::string page_type = encoding_attributes_["page_type"];
    // Page v1 is fully compressed, so we need to decompress first.
    // Note: This is true only if compression is enabled.
    if (page_type == "DATA_PAGE_V1") {
        auto decompressed_bytes = Decompress(plaintext, compression_);
        int leading_bytes_to_strip = CalculateLevelBytesLength(
            decompressed_bytes, encoding_attributes_converted_);
        return Split(decompressed_bytes, leading_bytes_to_strip);
    }

    // Page v2 is only compressed in the value bytes, the level bytes are always uncompressed.
    // So first split, then uncompress.
    if (page_type == "DATA_PAGE_V2") {
        int leading_bytes_to_strip = CalculateLevelBytesLength(
            plaintext, encoding_attributes_converted_);
        auto split_bytes = Split(plaintext, leading_bytes_to_strip);
        result.level_bytes = split_bytes.level_bytes;

        // Page V2 has an additional is_compressed bit.
        bool page_v2_is_compressed = std::get<bool>(
            encoding_attributes_converted_["page_v2_is_compressed"]);
        if (page_v2_is_compressed) {
            result.value_bytes = Decompress(split_bytes.value_bytes, compression_);
        } else {
            result.value_bytes = split_bytes.value_bytes;
        }
        return result;
    }

    if (page_type == "DICTIONARY_PAGE") {
        result.value_bytes = Decompress(plaintext, compression_);
        result.level_bytes = std::vector<uint8_t>();
        return result;
    }
    
    throw InvalidInputException("Unexpected page type: " + page_type);
}

// This is the primary integration point for Protegrity to encrypt individual items from a typed list.
// 
// Also the context rich encryptor can use these additional parameters: column_name, user_id, key_id, application_context.
//
// The current implementation prints out the list of items in the typed list and throws the DBPSUnsupportedException
// so that the default encryption method is used.
//
// Both the level_bytes AND elements need to be encrypted and combined as a single encrypted vector of bytes.
//
std::vector<uint8_t> DataBatchEncryptionSequencer::EncryptTypedList(
    const TypedListValues& typed_list, const std::vector<uint8_t>& level_bytes) {
   
    // Printout the typed list.
    auto print_result = PrintTypedList(typed_list);
    if (print_result.length() > 1000) {
        std::cout << "Encrypt value - Decoded plaintext data (first 1000 chars):\n" 
                << print_result.substr(0, 1000) << "...";
    } else {
        std::cout << "Encrypt value - Decoded plaintext data:\n" << print_result;
    }

    // Printout the additional context parameters.
    std::cout << "Context parameters:\n"
        << "  column_name: " << column_name_ << "\n"
        << "  user_id: " << user_id_ << "\n"
        << "  key_id: " << key_id_ << "\n"
        << "  application_context: " << application_context_  << "\n"
        << std::endl;

    throw DBPSUnsupportedException("EncryptTypedList not implemented");
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
    // 
    // The DBPS server version check during Decrypt is to future-proof against changes on the Encryption process.
    // The Encryption process could change due to updates on the payload decoding, updates on fallback encryption methods, or other changes,
    // and it is possible that it results on a mismatch with the Decryption implementation. This check helps to catch such mismatches.
    auto it = encryption_metadata_.find(DBPS_VERSION_KEY);
    if (it == encryption_metadata_.end()) {
        std::cerr << "ERROR: EncryptionSequencer - encryption_metadata must contain key '" << DBPS_VERSION_KEY << "'" << std::endl;
        error_stage_ = "decrypt_version_check";
        error_message_ = "encryption_metadata must contain key '" + std::string(DBPS_VERSION_KEY) + "'";
        return false;
    } else if (it->second.find(DBPS_VERSION_VALUE) != 0) {
        std::cerr << "ERROR: EncryptionSequencer - encryption_metadata['" << DBPS_VERSION_KEY << "'] must match '" 
                  << DBPS_VERSION_VALUE << "', but got '" << it->second << "'" << std::endl;
        error_stage_ = "decrypt_version_check";
        error_message_ = "encryption_metadata['" + std::string(DBPS_VERSION_KEY) + "'] must match '" + std::string(DBPS_VERSION_VALUE) + "'";
        return false;
    }
    
    // Simple XOR decryption (same operation as encryption)
    decrypted_result_ = DecryptData(ciphertext);
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
