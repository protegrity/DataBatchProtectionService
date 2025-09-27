#include "dbpa_remote.h"
#include "../client/dbps_api_client.h"
#include "../client/httplib_client.h"
#include "enum_utils.h"
#include <iostream>
#include <nlohmann/json.hpp>

using namespace dbps::external;
using namespace dbps::enum_utils;

RemoteEncryptionResult::RemoteEncryptionResult(std::unique_ptr<EncryptApiResponse> response)
    : response_(std::move(response)) {
}

span<const uint8_t> RemoteEncryptionResult::ciphertext() const {
    if (!response_ || !response_->Success()) {
        return span<const uint8_t>();
    }
    return response_->GetResponseCiphertext();
}

std::size_t RemoteEncryptionResult::size() const {
    if (!response_ || !response_->Success()) {
        return 0;
    }
    return response_->GetResponseCiphertext().size();
}

bool RemoteEncryptionResult::success() const {
    return response_ && response_->Success();
}

const std::string& RemoteEncryptionResult::error_message() const {
    if (cached_error_message_.empty() && response_) {
        if (!response_->Success()) {
            cached_error_message_ = response_->ErrorMessage();
        } else {
            cached_error_message_ = "Successful encryption";
        }
    }
    return cached_error_message_;
}

const std::map<std::string, std::string>& RemoteEncryptionResult::error_fields() const {
    if (cached_error_fields_.empty() && response_) {
        if (!response_->Success()) {
            cached_error_fields_ = response_->ErrorFields();
        }
    }
    return cached_error_fields_;
}

RemoteDecryptionResult::RemoteDecryptionResult(std::unique_ptr<DecryptApiResponse> response)
    : response_(std::move(response)) {
}

span<const uint8_t> RemoteDecryptionResult::plaintext() const {
    if (!response_ || !response_->Success()) {
        return span<const uint8_t>();
    }
    return response_->GetResponsePlaintext();
}

std::size_t RemoteDecryptionResult::size() const {
    if (!response_ || !response_->Success()) {
        return 0;
    }
    return response_->GetResponsePlaintext().size();
}

bool RemoteDecryptionResult::success() const {
    return response_ && response_->Success();
}

const std::string& RemoteDecryptionResult::error_message() const {
    if (cached_error_message_.empty() && response_) {
        if (!response_->Success()) {
            cached_error_message_ = response_->ErrorMessage();
        } else {
            cached_error_message_ = "Successful decryption";
        }
    }
    return cached_error_message_;
}

const std::map<std::string, std::string>& RemoteDecryptionResult::error_fields() const {
    if (cached_error_fields_.empty() && response_) {
        if (!response_->Success()) {
            cached_error_fields_ = response_->ErrorFields();
        }
    }
    return cached_error_fields_;
}

// Helper functions for validating that fields of the request <> response match.
static std::unique_ptr<DecryptApiResponse> ValidateDecryptFieldMatch(
    const std::string& response_value,
    const std::string& request_value,
    const std::string& field_name) {
    
    if (response_value != request_value) {
        std::string error_msg = "Decrypt response " + field_name + " mismatch: expected " + request_value + 
                               ", got " + response_value;
        std::cerr << "ERROR: Decrypt response " << field_name << " mismatch - request: " << request_value 
                  << ", response: " << response_value << std::endl;
        auto error_response = std::make_unique<DecryptApiResponse>();
        error_response->SetApiClientError(error_msg);
        return error_response;
    }
    return nullptr;
}

static std::unique_ptr<EncryptApiResponse> ValidateEncryptFieldMatch(
    const std::string& response_value,
    const std::string& request_value,
    const std::string& field_name) {
    
    if (response_value != request_value) {
        std::string error_msg = "Encrypt response " + field_name + " mismatch: expected " + request_value + 
                               ", got " + response_value;
        std::cerr << "ERROR: Encrypt response " << field_name << " mismatch - request: " << request_value 
                  << ", response: " << response_value << std::endl;
        auto error_response = std::make_unique<EncryptApiResponse>();
        error_response->SetApiClientError(error_msg);
        return error_response;
    }
    return nullptr;
}

RemoteDataBatchProtectionAgent::RemoteDataBatchProtectionAgent(std::shared_ptr<HttpClientInterface> http_client)
    : api_client_(std::make_unique<DBPSApiClient>(http_client)) {
    // API client is created immediately with the injected HTTP client
    // init() will still be called to set up configuration, but won't create a new client
}

void RemoteDataBatchProtectionAgent::init(
    std::string column_name,
    std::map<std::string, std::string> connection_config,
    std::string app_context,
    std::string column_key_id,
    Type::type datatype,
    std::optional<int> datatype_length,
    CompressionCodec::type compression_type) {

    std::cerr << "INFO: RemoteDataBatchProtectionAgent::init() - Starting initialization for column: " << column_name << std::endl;
    initialized_ = "Agent not properly initialized - incomplete"; 
        
    try {
        // Call the base class init to store the configuration
        DataBatchProtectionAgentInterface::init(
            std::move(column_name),
            std::move(connection_config),
            std::move(app_context),
            std::move(column_key_id),
            datatype,
            datatype_length,
            compression_type
        );

        // Either with the injected HTTP client or not, the server_url should be there.
        auto server_url_opt = ExtractServerUrl(connection_config_);
        if (!server_url_opt || server_url_opt->empty()) {
            std::cerr << "ERROR: RemoteDataBatchProtectionAgent::init() - No server_url provided in connection_config." << std::endl;
            initialized_ = "Agent not properly initialized - server_url missing";
            throw DBPSException("No server_url provided in connection_config");
        }
        server_url_ = *server_url_opt;
        std::cerr << "INFO: RemoteDataBatchProtectionAgent::init() - server_url extracted: [" << server_url_ << "]" << std::endl;

        // check for app_context not empty (as user_id will be extracted from it)
        if (app_context_.empty()) { 
            std::cerr << "ERROR: RemoteDataBatchProtectionAgent::init() - app_context is empty" << std::endl;
            initialized_ = "Agent not properly initialized - app_context is empty";
            throw DBPSException("app_context is empty");
        }

        // Extract user_id from app_context
        auto user_id_opt = ExtractUserId(app_context_);
        if (!user_id_opt || user_id_opt->empty()) {
            std::cerr << "ERROR: RemoteDataBatchProtectionAgent::init() - No user_id provided in app_context." << std::endl;
            initialized_ = "Agent not properly initialized - user_id missing";
            throw DBPSException("No user_id provided in app_context");
        }
        user_id_ = *user_id_opt;
        std::cerr << "INFO: RemoteDataBatchProtectionAgent::init() - user_id extracted: [" << user_id_ << "]" << std::endl;
        
        // Create API_client if not already created.
        // The API client constructor does not attemp a HTTPconnection with the server. The first Get/Post calls creates the HTTP connection.
        if (!api_client_) {
            std::cerr << "INFO: RemoteDataBatchProtectionAgent::init() - Creating API client for server: " << server_url_ << std::endl;
            auto http_client = std::make_shared<HttplibClient>(server_url_);
            api_client_ = std::make_unique<DBPSApiClient>(http_client);
        } else {
            std::cerr << "INFO: RemoteDataBatchProtectionAgent::init() - Using existing API client" << std::endl;
        }
        
        // Perform health check to verify server connectivity
        std::cerr << "INFO: RemoteDataBatchProtectionAgent::init() - Performing health check..." << std::endl;
        std::string health_response = api_client_->HealthCheck();
        if (health_response != "OK") {
            std::cerr << "ERROR: RemoteDataBatchProtectionAgent::init() - Health check returned unexpected response: " << health_response << std::endl;
            initialized_ = "Agent not properly initialized - healthz check failed";
            throw DBPSException("Health check failed: " + health_response);
        }
        std::cerr << "INFO: RemoteDataBatchProtectionAgent::init() - Health check successful: " << health_response << std::endl;

    } catch (const DBPSException& e) {
        // Re-throw DBPSException as-is.
        throw;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: RemoteDataBatchProtectionAgent::init() - Unexpected exception: " << e.what() << std::endl;
        initialized_ = "Agent not properly initialized - Unexpected exception: " + std::string(e.what());
        throw DBPSException("Unexpected exception during initialization: " + std::string(e.what()));
    }

    initialized_ = ""; // Empty string indicates successful initialization
    std::cerr << "INFO: RemoteDataBatchProtectionAgent::init() - Initialization completed successfully" << std::endl;
}

std::unique_ptr<EncryptionResult> RemoteDataBatchProtectionAgent::Encrypt(span<const uint8_t> plaintext,std::map<std::string, std::string> encoding_attributes) {
    if (!initialized_.has_value()) {
        // Return a result indicating initialization failure
        auto empty_response = std::make_unique<EncryptApiResponse>();
        empty_response->SetApiClientError("Agent not initialized - init() was not called");
        return std::make_unique<RemoteEncryptionResult>(std::move(empty_response));
    }
    
    if (!initialized_->empty()) {
        // Return a result indicating initialization failure with specific error
        auto empty_response = std::make_unique<EncryptApiResponse>();
        empty_response->SetApiClientError(*initialized_);
        return std::make_unique<RemoteEncryptionResult>(std::move(empty_response));
    }
    
    // Extract page_encoding from encoding_attributes and convert to Format::type
    auto format_opt = ExtractPageEncoding(encoding_attributes);
    if (!format_opt.has_value()) {
        std::cerr << "ERROR: RemoteDataBatchProtectionAgent::Encrypt() - page_encoding not found or invalid in encoding_attributes." << std::endl;
        auto empty_response = std::make_unique<EncryptApiResponse>();
        empty_response->SetApiClientError("page_encoding not found or invalid in encoding_attributes");
        return std::make_unique<RemoteEncryptionResult>(std::move(empty_response));
    }
    
    // Make the encryption call to the server
    auto response = api_client_->Encrypt(
        plaintext,
        column_name_,
        datatype_,
        datatype_length_,
        compression_type_,
        format_opt.value(),
        encoding_attributes,
        compression_type_,
        column_key_id_,
        user_id_
    );

    // Validate that response fields match request fields
    if (response.Success()) {
        const auto& response_attrs = response.GetResponseAttributes();
        
        // Validate encrypted compression matches request compression
        auto compression_error = ValidateEncryptFieldMatch(response_attrs.encrypted_compression_, 
                                                         std::string(to_string(compression_type_)), 
                                                         "encrypted_compression");
        if (compression_error) {
            return std::make_unique<RemoteEncryptionResult>(std::move(compression_error));
        }
    }
    
    // Wrap the API response in our result class
    return std::make_unique<RemoteEncryptionResult>(std::make_unique<EncryptApiResponse>(std::move(response)));
}

std::unique_ptr<DecryptionResult> RemoteDataBatchProtectionAgent::Decrypt(span<const uint8_t> ciphertext, std::map<std::string, std::string> encoding_attributes) {
    if (!initialized_.has_value()) {
        // Return a result indicating initialization failure
        auto empty_response = std::make_unique<DecryptApiResponse>();
        empty_response->SetApiClientError("Agent not initialized - init() was not called");
        return std::make_unique<RemoteDecryptionResult>(std::move(empty_response));
    }
    
    if (!initialized_->empty()) {
        // Return a result indicating initialization failure with specific error
        auto empty_response = std::make_unique<DecryptApiResponse>();
        empty_response->SetApiClientError(*initialized_);
        return std::make_unique<RemoteDecryptionResult>(std::move(empty_response));
    }
    
    // Extract page_encoding from encoding_attributes and convert to Format::type
    auto format_opt = ExtractPageEncoding(encoding_attributes);
    if (!format_opt.has_value()) {
        std::cerr << "ERROR: RemoteDataBatchProtectionAgent::Decrypt() - page_encoding not found or invalid in encoding_attributes." << std::endl;
        auto empty_response = std::make_unique<DecryptApiResponse>();
        empty_response->SetApiClientError("page_encoding not found or invalid in encoding_attributes");
        return std::make_unique<RemoteDecryptionResult>(std::move(empty_response));
    }
    
    // Make the decryption call to the server
    auto response = api_client_->Decrypt(
        ciphertext,
        column_name_,
        datatype_,
        datatype_length_,
        compression_type_,
        format_opt.value(),
        encoding_attributes,
        compression_type_,
        column_key_id_,
        user_id_
    );

    // Validate that response fields match request fields
    // TODO: Add validation for format when these are expanded beyond PLAIN.
    if (response.Success()) {
        const auto& response_attrs = response.GetResponseAttributes();
        
        // Validate datatype
        auto datatype_error = ValidateDecryptFieldMatch(response_attrs.datatype_, std::string(to_string(datatype_)), "datatype");
        if (datatype_error) {
            return std::make_unique<RemoteDecryptionResult>(std::move(datatype_error));
        }
        
        // Validate compression
        auto compression_error = ValidateDecryptFieldMatch(response_attrs.compression_, std::string(to_string(compression_type_)), "compression");
        if (compression_error) {
            return std::make_unique<RemoteDecryptionResult>(std::move(compression_error));
        }
    }

    // Wrap the API response in our result class
    return std::make_unique<RemoteDecryptionResult>(std::make_unique<DecryptApiResponse>(std::move(response)));
}

std::optional<std::string> RemoteDataBatchProtectionAgent::ExtractServerUrl(const std::map<std::string, std::string>& connection_config) const {
    auto it = connection_config.find("server_url");
    if (it != connection_config.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<std::string> RemoteDataBatchProtectionAgent::ExtractUserId(const std::string& app_context) const {
    try {
        auto json = nlohmann::json::parse(app_context);
        if (json.contains("user_id") && json["user_id"].is_string()) {
            std::string user_id = json["user_id"];
            if (!user_id.empty()) {
                return user_id;
            }
        }
    } catch (const nlohmann::json::exception& e) {
        std::cerr << "ERROR: RemoteDataBatchProtectionAgent::ExtractUserId() - Failed to parse app_context JSON: " << e.what() << std::endl;
    }
    return std::nullopt;
}

std::optional<Format::type> RemoteDataBatchProtectionAgent::ExtractPageEncoding(const std::map<std::string, std::string>& encoding_attributes) const {
    auto it = encoding_attributes.find("page_encoding");
    if (it != encoding_attributes.end()) {
        const std::string& encoding_str = it->second;
        auto format_opt = to_format_enum(encoding_str);
        if (format_opt.has_value()) {
            return format_opt.value();
        } else {
            std::cerr << "ERROR: RemoteDataBatchProtectionAgent::ExtractPageEncoding() - Unknown page_encoding: " << encoding_str << std::endl;
            return std::nullopt;
        }
    }
    // Return nullopt if page_encoding not found
    return std::nullopt;
}
