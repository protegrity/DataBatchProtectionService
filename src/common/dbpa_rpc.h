#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <optional>
#include "tcb/span.hpp"
#include "enums.h"
#include "dbpa_interface.h"
#include "../client/dbps_api_client.h"

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

namespace dbps::external {

/**
 * Implementation of EncryptionResult for remote calls that wraps EncryptApiResponse
 * Provides the required interface for encryption results from network calls
 */
class DBPS_EXPORT RemoteEncryptionResult : public EncryptionResult {
public:
    explicit RemoteEncryptionResult(std::unique_ptr<EncryptApiResponse> response);
    
    // EncryptionResult interface implementation
    span<const uint8_t> ciphertext() const override;
    std::size_t size() const override;
    bool success() const override;
    const std::string& error_message() const override;
    const std::map<std::string, std::string>& error_fields() const override;
    
    ~RemoteEncryptionResult() override = default;

private:
    std::unique_ptr<EncryptApiResponse> response_;

    // Cache error message/fields to avoid repeated parsing of API response.
    // Defined as mutable because it has lazy evaluation (updated only once on the getter methods)
    // The caching of this is possible because the API response `response_` doesn't change after construction.
    mutable std::string cached_error_message_;
    mutable std::map<std::string, std::string> cached_error_fields_;
};

/**
 * Implementation of DecryptionResult for remote calls that wraps DecryptApiResponse
 * Provides the required interface for decryption results from network calls
 */
class DBPS_EXPORT RemoteDecryptionResult : public DecryptionResult {
public:
    explicit RemoteDecryptionResult(std::unique_ptr<DecryptApiResponse> response);
    
    // DecryptionResult interface implementation
    span<const uint8_t> plaintext() const override;
    std::size_t size() const override;
    bool success() const override;
    const std::string& error_message() const override;
    const std::map<std::string, std::string>& error_fields() const override;
    
    ~RemoteDecryptionResult() override = default;

private:
    std::unique_ptr<DecryptApiResponse> response_;

    // Cached error message/fields to avoid repeated parsing of API response.
    // Defined as mutable because it has lazy evaluation (updated only once on the getter methods)
    mutable std::string cached_error_message_;
    mutable std::map<std::string, std::string> cached_error_fields_;
};

/**
 * Implementation of DataBatchProtectionAgentInterface for remote calls
 * Uses DBPSApiClient to make network calls to the DBPS server for encryption/decryption
 */
class DBPS_EXPORT RemoteDataBatchProtectionAgent : public DataBatchProtectionAgentInterface {
public:
    // Constructor (default). Creates API_client during init() using server_url from connection_config
    RemoteDataBatchProtectionAgent() = default;
    
    // Constructor with HTTP client passed. Creates API_client immediately on the contructor.
    explicit RemoteDataBatchProtectionAgent(std::unique_ptr<HttpClientInterface> http_client);
    
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
    
    ~RemoteDataBatchProtectionAgent() override = default;

protected:
    // Configuration state
    // std::nullopt = not initialized, "error message" = failed, "" = success
    std::optional<std::string> initialized_;
    std::string server_url_;
    std::string user_id_;

private:
    // Helper methods for configuration parsing
    std::optional<std::string> ExtractServerUrl(const std::map<std::string, std::string>& connection_config) const;
    std::optional<std::string> ExtractUserId(const std::string& app_context) const;
    
    // Client instance
    std::unique_ptr<DBPSApiClient> api_client_;
};

} // namespace dbps::external
