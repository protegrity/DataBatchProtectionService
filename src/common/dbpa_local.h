#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <optional>
#include "tcb/span.hpp"
#include "enums.h"
#include "dbpa_interface.h"

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

namespace dbps::external {

/**
 * Implementation of EncryptionResult for local calls that wraps DataBatchEncryptionSequencer results
 * Provides the required interface for encryption results from direct sequencer calls
 */
class DBPS_EXPORT LocalEncryptionResult : public EncryptionResult {
public:
    // Constructor for successful encryption
    LocalEncryptionResult(std::vector<uint8_t> ciphertext);
    
    // Constructor for failed encryption
    LocalEncryptionResult(const std::string& error_stage, const std::string& error_message);
    
    // EncryptionResult interface implementation
    span<const uint8_t> ciphertext() const override;
    std::size_t size() const override;
    bool success() const override;
    const std::string& error_message() const override;
    const std::map<std::string, std::string>& error_fields() const override;
    
    ~LocalEncryptionResult() override = default;

private:
    std::vector<uint8_t> ciphertext_;
    bool success_;
    std::string error_message_;
    std::map<std::string, std::string> error_fields_;
};

/**
 * Implementation of DecryptionResult for local calls that wraps DataBatchEncryptionSequencer results
 * Provides the required interface for decryption results from direct sequencer calls
 */
class DBPS_EXPORT LocalDecryptionResult : public DecryptionResult {
public:
    // Constructor for successful decryption
    LocalDecryptionResult(std::vector<uint8_t> plaintext);
    
    // Constructor for failed decryption
    LocalDecryptionResult(const std::string& error_stage, const std::string& error_message);
    
    // DecryptionResult interface implementation
    span<const uint8_t> plaintext() const override;
    std::size_t size() const override;
    bool success() const override;
    const std::string& error_message() const override;
    const std::map<std::string, std::string>& error_fields() const override;
    
    ~LocalDecryptionResult() override = default;

private:
    std::vector<uint8_t> plaintext_;
    bool success_;
    std::string error_message_;
    std::map<std::string, std::string> error_fields_;
};

/**
 * Implementation of DataBatchProtectionAgentInterface for local calls
 * Calls DataBatchEncryptionSequencer directly without any network communication
 */
class DBPS_EXPORT LocalDataBatchProtectionAgent : public DataBatchProtectionAgentInterface {
public:
    // Constructor
    LocalDataBatchProtectionAgent() = default;
    
    // DataBatchProtectionAgentInterface implementation
    void init(
        std::string column_name,
        std::map<std::string, std::string> connection_config,
        std::string app_context,
        std::string column_key_id,
        Type::type datatype,
        std::optional<int> datatype_length,
        CompressionCodec::type compression_type) override;
    
    std::unique_ptr<EncryptionResult> Encrypt(
        span<const uint8_t> plaintext,
        std::map<std::string, std::string> encoding_attributes) override;
    
    std::unique_ptr<DecryptionResult> Decrypt(
        span<const uint8_t> ciphertext,
        std::map<std::string, std::string> encoding_attributes) override;
    
    ~LocalDataBatchProtectionAgent() override = default;

protected:
    // Configuration state
    // std::nullopt = not initialized, "error message" = failed, "" = success
    std::optional<std::string> initialized_;
    std::string user_id_;
};

} // namespace dbps::external
