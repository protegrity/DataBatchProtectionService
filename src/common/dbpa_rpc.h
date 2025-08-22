#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include "tcb/span.hpp"
#include "enums.h"
#include "dbpa_interface.h"

// Forward declarations
namespace dbps::external {
    class DBPSApiClient;
    class EncryptApiResponse;
    class DecryptApiResponse;
    class HttpClientInterface;
}

using tcb::span;

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

namespace dbps::external {

/**
 * RPC implementation of EncryptionResult that wraps EncryptApiResponse
 * Provides the required interface for encryption results from network calls
 */
class DBPS_EXPORT RPCEncryptionResult : public EncryptionResult {
public:
    explicit RPCEncryptionResult(std::unique_ptr<EncryptApiResponse> response);
    
    // EncryptionResult interface implementation
    span<const uint8_t> ciphertext() const override;
    std::size_t size() const override;
    bool success() const override;
    const std::string& error_message() const override;
    const std::map<std::string, std::string>& error_fields() const override;
    
    ~RPCEncryptionResult() override = default;

private:
    std::unique_ptr<EncryptApiResponse> response_;
    mutable std::string cached_error_message_;
    mutable std::map<std::string, std::string> cached_error_fields_;
};

/**
 * RPC implementation of DecryptionResult that wraps DecryptApiResponse
 * Provides the required interface for decryption results from network calls
 */
class DBPS_EXPORT RPCDecryptionResult : public DecryptionResult {
public:
    explicit RPCDecryptionResult(std::unique_ptr<DecryptApiResponse> response);
    
    // DecryptionResult interface implementation
    span<const uint8_t> plaintext() const override;
    std::size_t size() const override;
    bool success() const override;
    const std::string& error_message() const override;
    const std::map<std::string, std::string>& error_fields() const override;
    
    ~RPCDecryptionResult() override = default;

private:
    std::unique_ptr<DecryptApiResponse> response_;
    mutable std::string cached_error_message_;
    mutable std::map<std::string, std::string> cached_error_fields_;
};

/**
 * RPC implementation of DataBatchProtectionAgentInterface
 * Uses DBPSApiClient to make network calls to the DBPS server for encryption/decryption
 */
class DBPS_EXPORT RPCDataBatchProtectionAgent : public DataBatchProtectionAgentInterface {
public:
    // Constructor (default). Creates API_client during init() using server_url from connection_config
    RPCDataBatchProtectionAgent() = default;
    
    // Constructor with HTTP client passed. Creates API_client immediately on the contructor.
    explicit RPCDataBatchProtectionAgent(std::unique_ptr<HttpClientInterface> http_client);
    
    // DataBatchProtectionAgentInterface implementation
    void init(
        std::string column_name,
        std::map<std::string, std::string> connection_config,
        std::string app_context,
        std::string column_key_id,
        Type::type data_type,
        CompressionCodec::type compression_type) override;
    
    std::unique_ptr<EncryptionResult> Encrypt(
        span<const uint8_t> plaintext) override;
    
    std::unique_ptr<DecryptionResult> Decrypt(
        span<const uint8_t> ciphertext) override;
    
    ~RPCDataBatchProtectionAgent() override = default;

private:
    // Helper methods for configuration parsing
    std::optional<std::string> ExtractServerUrl(const std::map<std::string, std::string>& connection_config) const;
    std::optional<std::string> ExtractUserId(const std::string& app_context) const;
    
    // Client instance
    std::unique_ptr<DBPSApiClient> api_client_;
    
    // Configuration state
    bool initialized_ = false;
    std::string server_url_;
    std::string user_id_;
};

} // namespace dbps::external
