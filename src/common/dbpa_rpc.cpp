#include "dbpa_rpc.h"
#include "../client/dbps_api_client.h"
#include <iostream>
#include <nlohmann/json.hpp>

using namespace dbps::external;

RPCEncryptionResult::RPCEncryptionResult(std::unique_ptr<EncryptApiResponse> response)
    : response_(std::move(response)) {
}

span<const uint8_t> RPCEncryptionResult::ciphertext() const {
    if (!response_ || !response_->Success()) {
        return span<const uint8_t>();
    }
    return response_->GetResponseCiphertext();
}

std::size_t RPCEncryptionResult::size() const {
    if (!response_ || !response_->Success()) {
        return 0;
    }
    return response_->GetResponseCiphertext().size();
}

bool RPCEncryptionResult::success() const {
    return response_ && response_->Success();
}

const std::string& RPCEncryptionResult::error_message() const {
    if (cached_error_message_.empty() && response_) {
        if (!response_->Success()) {
            cached_error_message_ = response_->ErrorMessage();
        } else {
            cached_error_message_ = "Successful encryption";
        }
    }
    return cached_error_message_;
}

const std::map<std::string, std::string>& RPCEncryptionResult::error_fields() const {
    if (cached_error_fields_.empty() && response_) {
        if (!response_->Success()) {
            cached_error_fields_ = response_->ErrorFields();
        }
    }
    return cached_error_fields_;
}

RPCDecryptionResult::RPCDecryptionResult(std::unique_ptr<DecryptApiResponse> response)
    : response_(std::move(response)) {
}

span<const uint8_t> RPCDecryptionResult::plaintext() const {
    if (!response_ || !response_->Success()) {
        return span<const uint8_t>();
    }
    return response_->GetResponsePlaintext();
}

std::size_t RPCDecryptionResult::size() const {
    if (!response_ || !response_->Success()) {
        return 0;
    }
    return response_->GetResponsePlaintext().size();
}

bool RPCDecryptionResult::success() const {
    return response_ && response_->Success();
}

const std::string& RPCDecryptionResult::error_message() const {
    if (cached_error_message_.empty() && response_) {
        if (!response_->Success()) {
            cached_error_message_ = response_->ErrorMessage();
        } else {
            cached_error_message_ = "Successful decryption";
        }
    }
    return cached_error_message_;
}

const std::map<std::string, std::string>& RPCDecryptionResult::error_fields() const {
    if (cached_error_fields_.empty() && response_) {
        if (!response_->Success()) {
            cached_error_fields_ = response_->ErrorFields();
        }
    }
    return cached_error_fields_;
}

RPCDataBatchProtectionAgent::RPCDataBatchProtectionAgent(std::unique_ptr<HttpClientInterface> http_client)
    : api_client_(std::make_unique<DBPSApiClient>(std::move(http_client))) {
    // API client is created immediately with the injected HTTP client
    // init() will still be called to set up configuration, but won't create a new client
}

void RPCDataBatchProtectionAgent::init(
    std::string column_name,
    std::map<std::string, std::string> connection_config,
    std::string app_context,
    std::string column_key_id,
    Type::type data_type,
    CompressionCodec::type compression_type) {
    
    // Call the base class init to store the configuration
    // +++++ Check if needed since superclass is virtual ++++++++  
    DataBatchProtectionAgentInterface::init(
        std::move(column_name),
        std::move(connection_config),
        std::move(app_context),
        std::move(column_key_id),
        data_type,
        compression_type
    );
    
    // Either with the injected HTTP client or not, the server_url should be there.
    auto server_url_opt = ExtractServerUrl(connection_config_);
    if (!server_url_opt || server_url_opt->empty()) {
        std::cerr << "ERROR: RPCDataBatchProtectionAgent::init() - No server URL provided in connection_config." << std::endl;
        return;
    }
    server_url_ = *server_url_opt;
    
    // Extract user ID from app context
    auto user_id_opt = ExtractUserId(app_context_);
    if (!user_id_opt || user_id_opt->empty()) {
        std::cerr << "ERROR: RPCDataBatchProtectionAgent::init() - No user ID provided in app_context." << std::endl;
        return;
    }
    user_id_ = *user_id_opt;
    
    // Create API_client if not already created
    if (!api_client_) {
        api_client_ = std::make_unique<DBPSApiClient>(server_url_);
    }
    
    // Perform health check to verify server connectivity
    try {
        std::string health_response = api_client_->HealthCheck();
        if (health_response != "OK") {
            std::cerr << "ERROR: RPCDataBatchProtectionAgent::init() - Health check returned unexpected response: " << health_response << std::endl;
            return;
        }
    } catch (const std::exception& e) {
        std::cerr << "ERROR: RPCDataBatchProtectionAgent::init() - Health check failed: " << e.what() << std::endl;
        return;
    }
    
    initialized_ = true;
}

std::unique_ptr<EncryptionResult> RPCDataBatchProtectionAgent::Encrypt(span<const uint8_t> plaintext) {
    if (!initialized_) {
        // Return a result indicating initialization failure
        auto empty_response = std::make_unique<EncryptApiResponse>();
        empty_response->SetApiClientError("Agent not properly initialized");
        return std::make_unique<RPCEncryptionResult>(std::move(empty_response));
    }
    
    // Make the encryption call to the server
    auto response = api_client_->Encrypt(
        plaintext,
        column_name_,
        data_type_,
        compression_type_,
        Format::RAW_C_DATA,  // Currently only RAW_C_DATA is supported
        compression_type_,
        column_key_id_,
        user_id_
    );
    
    // Wrap the response in our result class
    return std::make_unique<RPCEncryptionResult>(std::make_unique<EncryptApiResponse>(std::move(response)));
}

std::unique_ptr<DecryptionResult> RPCDataBatchProtectionAgent::Decrypt(span<const uint8_t> ciphertext) {
    if (!initialized_) {
        // Return a result indicating initialization failure
        auto empty_response = std::make_unique<DecryptApiResponse>();
        empty_response->SetApiClientError("Agent not properly initialized");
        return std::make_unique<RPCDecryptionResult>(std::move(empty_response));
    }
    
    // Make the decryption call to the server
    auto response = api_client_->Decrypt(
        ciphertext,
        column_name_,
        data_type_,
        compression_type_,
        Format::RAW_C_DATA,  // Currently only RAW_C_DATA is supported
        compression_type_,
        column_key_id_,
        user_id_
    );

    // Wrap the response in our result class
    return std::make_unique<RPCDecryptionResult>(std::make_unique<DecryptApiResponse>(std::move(response)));
}

std::optional<std::string> RPCDataBatchProtectionAgent::ExtractServerUrl(const std::map<std::string, std::string>& connection_config) const {
    auto it = connection_config.find("server_url");
    if (it != connection_config.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<std::string> RPCDataBatchProtectionAgent::ExtractUserId(const std::string& app_context) const {
    if (app_context.empty()) {
        return std::nullopt;
    }
    try {
        auto json = nlohmann::json::parse(app_context);
        if (json.contains("user_id") && json["user_id"].is_string()) {
            std::string user_id = json["user_id"];
            if (!user_id.empty()) {
                return user_id;
            }
        }
    } catch (const nlohmann::json::exception& e) {
        std::cerr << "ERROR: RPCDataBatchProtectionAgent::ExtractUserId() - Failed to parse app_context JSON: " << e.what() << std::endl;
    }
    return std::nullopt;
}
