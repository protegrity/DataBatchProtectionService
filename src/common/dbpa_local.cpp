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

#include "dbpa_local.h"
#include "../server/encryption_sequencer.h"
#include "enum_utils.h"
#include "dbpa_utils.h"
#include <iostream>
#include <nlohmann/json.hpp>

using namespace dbps::external;
using namespace dbps::enum_utils;

// LocalEncryptionResult implementation

LocalEncryptionResult::LocalEncryptionResult(std::vector<uint8_t> ciphertext, const std::map<std::string, std::string>& encryption_metadata)
    : ciphertext_(std::move(ciphertext)),
      success_(true),
      encryption_metadata_(encryption_metadata) {
}

LocalEncryptionResult::LocalEncryptionResult(const std::string& error_stage, const std::string& error_message)
    : success_(false), error_message_(error_stage + ": " + error_message) {
    error_fields_["error_stage"] = error_stage;
    error_fields_["error_detail"] = error_message;
}

span<const uint8_t> LocalEncryptionResult::ciphertext() const {
    if (!success_) {
        return span<const uint8_t>();
    }
    return span<const uint8_t>(ciphertext_.data(), ciphertext_.size());
}

std::size_t LocalEncryptionResult::size() const {
    if (!success_) {
        return 0;
    }
    return ciphertext_.size();
}

bool LocalEncryptionResult::success() const {
    return success_;
}

const std::optional<std::map<std::string, std::string>> LocalEncryptionResult::encryption_metadata() const {
    return encryption_metadata_.empty() ? std::nullopt : std::optional{encryption_metadata_};
}

const std::string& LocalEncryptionResult::error_message() const {
    return error_message_;
}

const std::map<std::string, std::string>& LocalEncryptionResult::error_fields() const {
    return error_fields_;
}

// LocalDecryptionResult implementation

LocalDecryptionResult::LocalDecryptionResult(std::vector<uint8_t> plaintext)
    : plaintext_(std::move(plaintext)), success_(true) {
}

LocalDecryptionResult::LocalDecryptionResult(const std::string& error_stage, const std::string& error_message)
    : success_(false), error_message_(error_stage + ": " + error_message) {
    error_fields_["error_stage"] = error_stage;
    error_fields_["error_detail"] = error_message;
}

span<const uint8_t> LocalDecryptionResult::plaintext() const {
    if (!success_) {
        return span<const uint8_t>();
    }
    return span<const uint8_t>(plaintext_.data(), plaintext_.size());
}

std::size_t LocalDecryptionResult::size() const {
    if (!success_) {
        return 0;
    }
    return plaintext_.size();
}

bool LocalDecryptionResult::success() const {
    return success_;
}

const std::string& LocalDecryptionResult::error_message() const {
    return error_message_;
}

const std::map<std::string, std::string>& LocalDecryptionResult::error_fields() const {
    return error_fields_;
}

// LocalDataBatchProtectionAgent implementation

void LocalDataBatchProtectionAgent::init(
    std::string column_name,
    std::map<std::string, std::string> configuration_map,
    std::string app_context,
    std::string column_key_id,
    Type::type datatype,
    std::optional<int> datatype_length,
    CompressionCodec::type compression_type,
    std::optional<std::map<std::string, std::string>> column_encryption_metadata) {

    std::cerr << "INFO: LocalDataBatchProtectionAgent::init() - Starting initialization for column: " << column_name << std::endl;
    initialized_ = "Agent not properly initialized - incomplete";
    
    try {
        // Call the base class init to store the configuration
        DataBatchProtectionAgentInterface::init(
            std::move(column_name),
            std::move(configuration_map),
            std::move(app_context),
            std::move(column_key_id),
            datatype,
            datatype_length,
            compression_type,
            std::move(column_encryption_metadata)
        );

        // Check for app_context not empty (as user_id will be extracted from it)
        if (app_context_.empty()) {
            std::cerr << "ERROR: LocalDataBatchProtectionAgent::init() - app_context is empty" << std::endl;
            initialized_ = "Agent not properly initialized - app_context is empty";
            throw DBPSException("app_context is empty");
        }

        // Extract user_id from app_context
        auto user_id_opt = dbps::external::ExtractUserId(app_context_);
        if (!user_id_opt || user_id_opt->empty()) {
            std::cerr << "ERROR: LocalDataBatchProtectionAgent::init() - No user_id provided in app_context." << std::endl;
            initialized_ = "Agent not properly initialized - user_id missing";
            throw DBPSException("No user_id provided in app_context");
        }
        user_id_ = *user_id_opt;
        std::cerr << "INFO: LocalDataBatchProtectionAgent::init() - user_id extracted: [" << user_id_ << "]" << std::endl;

    } catch (const DBPSException& e) {
        // Re-throw DBPSException as-is
        throw;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: LocalDataBatchProtectionAgent::init() - Unexpected exception: " << e.what() << std::endl;
        initialized_ = "Agent not properly initialized - Unexpected exception: " + std::string(e.what());
        throw DBPSException("Unexpected exception during initialization: " + std::string(e.what()));
    }

    initialized_ = ""; // Empty string indicates successful initialization
    std::cerr << "INFO: LocalDataBatchProtectionAgent::init() - Initialization completed successfully" << std::endl;
}

std::unique_ptr<EncryptionResult> LocalDataBatchProtectionAgent::Encrypt(
    span<const uint8_t> plaintext,
    std::map<std::string, std::string> encoding_attributes) {
    
    if (!initialized_.has_value()) {
        // Return a result indicating initialization failure
        return std::make_unique<LocalEncryptionResult>("initialization", "Agent not initialized - init() was not called");
    }
    
    if (!initialized_->empty()) {
        // Return a result indicating initialization failure with specific error
        return std::make_unique<LocalEncryptionResult>("initialization", *initialized_);
    }
    
    // Extract page_encoding from encoding_attributes and convert to Format::type
    auto format_opt = dbps::external::ExtractPageEncoding(encoding_attributes);
    if (!format_opt.has_value()) {
        std::cerr << "ERROR: LocalDataBatchProtectionAgent::Encrypt() - page_encoding not found or invalid in encoding_attributes." << std::endl;
        return std::make_unique<LocalEncryptionResult>("parameter_validation", "page_encoding not found or invalid in encoding_attributes");
    }
    
    // Create the DataBatchEncryptionSequencer
    DataBatchEncryptionSequencer sequencer(
        column_name_,
        datatype_,
        datatype_length_,
        compression_type_,
        format_opt.value(),
        encoding_attributes,
        compression_type_,
        column_key_id_,
        user_id_,
        app_context_,
        {}  // encryption_metadata, which is empty for the Encryption call.
    );
    
    // Convert plaintext span to vector for the sequencer
    std::vector<uint8_t> plaintext_vec(plaintext.begin(), plaintext.end());
    
    // Call the sequencer to encrypt
    bool encrypt_result = sequencer.ConvertAndEncrypt(plaintext_vec);
    if (!encrypt_result) {
        std::cerr << "ERROR: LocalDataBatchProtectionAgent::Encrypt() - Encryption failed: " 
                  << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
        return std::make_unique<LocalEncryptionResult>(sequencer.error_stage_, sequencer.error_message_);
    }
    
    // Return successful result with encrypted data and encryption_metadata
    return std::make_unique<LocalEncryptionResult>(std::move(sequencer.encrypted_result_), sequencer.encryption_metadata_);
}

std::unique_ptr<DecryptionResult> LocalDataBatchProtectionAgent::Decrypt(
    span<const uint8_t> ciphertext,
    std::map<std::string, std::string> encoding_attributes) {
    
    if (!initialized_.has_value()) {
        // Return a result indicating initialization failure
        return std::make_unique<LocalDecryptionResult>("initialization", "Agent not initialized - init() was not called");
    }
    
    if (!initialized_->empty()) {
        // Return a result indicating initialization failure with specific error
        return std::make_unique<LocalDecryptionResult>("initialization", *initialized_);
    }
    
    // Extract page_encoding from encoding_attributes and convert to Format::type
    auto format_opt = dbps::external::ExtractPageEncoding(encoding_attributes);
    if (!format_opt.has_value()) {
        std::cerr << "ERROR: LocalDataBatchProtectionAgent::Decrypt() - page_encoding not found or invalid in encoding_attributes." << std::endl;
        return std::make_unique<LocalDecryptionResult>("parameter_validation", "page_encoding not found or invalid in encoding_attributes");
    }
    
    // Create the DataBatchEncryptionSequencer
    DataBatchEncryptionSequencer sequencer(
        column_name_,
        datatype_,
        datatype_length_,
        compression_type_,
        format_opt.value(),
        encoding_attributes,
        compression_type_,
        column_key_id_,
        user_id_,
        app_context_,
        column_encryption_metadata_.value_or(std::map<std::string, std::string>{})
    );
    
    // Convert ciphertext span to vector for the sequencer
    std::vector<uint8_t> ciphertext_vec(ciphertext.begin(), ciphertext.end());
    
    // Call the sequencer to decrypt
    bool decrypt_result = sequencer.ConvertAndDecrypt(ciphertext_vec);
    if (!decrypt_result) {
        std::cerr << "ERROR: LocalDataBatchProtectionAgent::Decrypt() - Decryption failed: " 
                  << sequencer.error_stage_ << " - " << sequencer.error_message_ << std::endl;
        return std::make_unique<LocalDecryptionResult>(sequencer.error_stage_, sequencer.error_message_);
    }
    
    // Return successful result with decrypted data
    return std::make_unique<LocalDecryptionResult>(std::move(sequencer.decrypted_result_));
}

