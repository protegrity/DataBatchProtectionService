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
#include "../client/httplib_pool_registry.h"
#include <nlohmann/json.hpp>

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
    const std::optional<std::map<std::string, std::string>> encryption_metadata() const override;
    const std::string& error_message() const override;
    const std::map<std::string, std::string>& error_fields() const override;
    
    ~RemoteEncryptionResult() override = default;

private:
    std::unique_ptr<EncryptApiResponse> response_;

    // Stored error message/fields/encryption_metadata to avoid repeated parsing of API response.
    // Defined as mutable because it has lazy evaluation (updated only once on the getter methods)
    // The caching of this is possible because the API response `response_` doesn't change after construction.
    mutable std::string parsed_error_message_;
    mutable std::map<std::string, std::string> parsed_error_fields_;
    mutable std::optional<std::map<std::string, std::string>> parsed_encryption_metadata_;
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

    // Stored error message/fields to avoid repeated parsing of API response.
    // Defined as mutable because it has lazy evaluation (updated only once on the getter methods)
    mutable std::string parsed_error_message_;
    mutable std::map<std::string, std::string> parsed_error_fields_;
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
    explicit RemoteDataBatchProtectionAgent(std::shared_ptr<HttpClientInterface> http_client);
    
    // DataBatchProtectionAgentInterface implementation
    void init(
        std::string column_name,
        std::map<std::string, std::string> connection_config,
        std::string app_context,
        std::string column_key_id,
        Type::type datatype,
        std::optional<int> datatype_length,
        CompressionCodec::type compression_type,
        std::optional<std::map<std::string, std::string>> column_encryption_metadata) override;
    
    std::unique_ptr<EncryptionResult> Encrypt(
        span<const uint8_t> plaintext,
        std::map<std::string, std::string> encoding_attributes) override;
    
    std::unique_ptr<DecryptionResult> Decrypt(
        span<const uint8_t> ciphertext,
        std::map<std::string, std::string> encoding_attributes) override;
    
    ~RemoteDataBatchProtectionAgent() override = default;

protected:
    // Configuration state
    // std::nullopt = not initialized, "error message" = failed, "" = success
    std::optional<std::string> initialized_;
    std::string server_url_;
    std::string user_id_;
    std::string k_connection_config_key_ = "connection_config_file_path";

    // Extract pool config from connection_config
    // assumes all values in connection_config are optional, and will use default values if any not present.
    HttplibPoolRegistry::PoolConfig ExtractPoolConfig(const nlohmann::json& config_json);
    // Extract number of worker threads for pooled client; defaults to 0 (auto)
    std::size_t ExtractNumWorkerThreads(const nlohmann::json& config_json) const;

private:
    // Helper methods for configuration parsing

    // Load and parse the connection config file specified in connection_config
    std::optional<nlohmann::json> LoadConnectionConfigFile(const std::map<std::string, std::string>& connection_config) const;

    // Instantiate a new HTTP client using the connection config file
    std::shared_ptr<HttpClientInterface> InstantiateHttpClient();

    // Extract server_url from parsed JSON config such as {"server_url": "http://localhost:8080"}
    std::optional<std::string> ExtractServerUrl(const nlohmann::json& config_json) const;

    std::optional<std::string> ExtractUserId(const std::string& app_context) const;
    std::optional<Format::type> ExtractPageEncoding(const std::map<std::string, std::string>& encoding_attributes) const;
    
    // Client instance
    std::unique_ptr<DBPSApiClient> api_client_;
};

} // namespace dbps::external
