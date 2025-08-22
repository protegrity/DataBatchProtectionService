// Project includes
#include "dbps_api_client.h"
#include "httplib_client.h"

// Standard library includes
#include <sstream>
#include <stdexcept>
#include <chrono>

// Third-party library includes
#include <cppcodec/base64_rfc4648.hpp>

using namespace dbps::external;
using namespace dbps::enum_utils;
using tcb::span;

// Auxiliary function for base64 encoding
std::optional<std::string> EncodeBase64(span<const uint8_t> data) {
    try {
        // Use cppcodec library for robust base64 encoding
        return cppcodec::base64_rfc4648::encode(data);
    } catch (const std::exception& e) {
        // Return empty optional on any encoding error
        return std::nullopt;
    }
}

// Auxiliary function for base64 decoding
std::optional<std::vector<uint8_t>> DecodeBase64(const std::string& base64_string) {
    try {
        // Use cppcodec library for robust base64 decoding
        return cppcodec::base64_rfc4648::decode(base64_string);
    } catch (const std::exception& e) {
        // Return empty optional on any decoding error
        return std::nullopt;
    }
}

// Generate a simple unique reference ID using timestamp
std::string GenerateReferenceId() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    return std::to_string(timestamp);
}

// Auxiliary function to check if HTTP status code indicates success
bool IsHttpSuccess(int status_code) {
    return status_code >= 200 && status_code < 300;
}

// ApiResponse method implementations
void ApiResponse::SetHttpStatusCode(int code) { http_status_code_ = code; }
void ApiResponse::SetApiClientError(const std::string& error) { api_client_error_ = error; }

void ApiResponse::SetRawResponse(const std::string& raw_response) { raw_response_ = raw_response; }

bool ApiResponse::HasHttpStatusCode() const { return http_status_code_.has_value(); }
bool ApiResponse::HasApiClientError() const { return api_client_error_.has_value(); }

bool ApiResponse::HasRawResponse() const { return raw_response_.has_value(); }

int ApiResponse::GetHttpStatusCode() const { return http_status_code_.value(); }
const std::string& ApiResponse::GetApiClientError() const { return api_client_error_.value(); }

const std::string& ApiResponse::GetRawResponse() const { return raw_response_.value(); }

bool ApiResponse::Success() const {
    return !HasApiClientError() && HasJsonResponse() && GetJsonResponse().IsValid() &&
           HasHttpStatusCode() && IsHttpSuccess(GetHttpStatusCode());
}

std::string ApiResponse::ErrorMessage() const {
    if (HasApiClientError()) return "API client error";
    if (!HasHttpStatusCode()) return "No HTTP status code";
    if (!IsHttpSuccess(GetHttpStatusCode())) return "Non-2xx HTTP status code";
    if (!HasJsonResponse()) return "No JSON response";
    if (!GetJsonResponse().IsValid()) return "Invalid JSON response";
    return "Successful call";
}

std::map<std::string, std::string> ApiResponse::ErrorFields() const {
    std::map<std::string, std::string> fields;
    
    if (HasJsonRequest()) {
        fields["request_string"] = GetJsonRequest().ToJson();
        fields["request_validation"] = GetJsonRequest().GetValidationError();
        fields["request_is_valid"] = GetJsonRequest().IsValid() ? "true" : "false";
    }
    
    if (HasRawResponse()) {
        fields["response_string"] = GetRawResponse();
    }
    
    if (HasJsonResponse()) {
        fields["response_validation"] = GetJsonResponse().GetValidationError();
        fields["response_is_valid"] = GetJsonResponse().IsValid() ? "true" : "false";
    }
    
    if (HasHttpStatusCode()) {
        fields["http_status_code"] = std::to_string(GetHttpStatusCode());
    }
    
    if (HasApiClientError()) {
        fields["api_client_error"] = GetApiClientError();
    }
    
    return fields;
}

// EncryptApiResponse method implementations
void EncryptApiResponse::SetJsonResponse(const EncryptJsonResponse& response) { 
    if (response.IsValid()) {
        auto decoded = DecodeBase64(response.encrypted_value_);
        if (decoded.has_value()) {
            decoded_ciphertext_ = decoded.value();
        } else {
            decoded_ciphertext_.reset();
        }
    } else {
        decoded_ciphertext_.reset();
    }
    encrypt_response_ = response;
}
const EncryptJsonResponse& EncryptApiResponse::GetJsonResponse() const { return encrypt_response_.value(); }
bool EncryptApiResponse::HasJsonResponse() const { return encrypt_response_.has_value(); }

span<const uint8_t> EncryptApiResponse::GetResponseCiphertext() const {
    // Adding the null check for safety, but in regular flows, the method is not called unless various checks pass.
    if (!decoded_ciphertext_.has_value()) {
        std::cerr << "ERROR: GetResponseCiphertext() called but decoded_ciphertext_ is not available" << std::endl;
        return span<const uint8_t>();
    }
    return span<const uint8_t>(decoded_ciphertext_.value());
}

const EncryptJsonResponse& EncryptApiResponse::GetResponseAttributes() const {
    return GetJsonResponse();
}

void EncryptApiResponse::SetJsonRequest(const EncryptJsonRequest& request) { json_request_ = request; }
bool EncryptApiResponse::HasJsonRequest() const { return json_request_.has_value(); }
const JsonRequest& EncryptApiResponse::GetJsonRequest() const { return json_request_.value(); }

// DecryptApiResponse method implementations
void DecryptApiResponse::SetJsonResponse(const DecryptJsonResponse& response) { 
    if (response.IsValid()) {
        auto decoded = DecodeBase64(response.decrypted_value_);
        if (decoded.has_value()) {
            decoded_plaintext_ = decoded.value();
        } else {
            decoded_plaintext_.reset();
        }
    } else {
        decoded_plaintext_.reset();
    }
    decrypt_response_ = response;
}
const DecryptJsonResponse& DecryptApiResponse::GetJsonResponse() const { return decrypt_response_.value(); }
bool DecryptApiResponse::HasJsonResponse() const { return decrypt_response_.has_value(); }

span<const uint8_t> DecryptApiResponse::GetResponsePlaintext() const {
    // Adding the null check for safety, but in regular flows, the method is not called unless various checks pass.
    if (!decoded_plaintext_.has_value()) {
        std::cerr << "ERROR: GetResponsePlaintext() called but decoded_plaintext_ is not available" << std::endl;
        return span<const uint8_t>();
    }
    return span<const uint8_t>(decoded_plaintext_.value());
}

const DecryptJsonResponse& DecryptApiResponse::GetResponseAttributes() const {
    return GetJsonResponse();
}

void DecryptApiResponse::SetJsonRequest(const DecryptJsonRequest& request) { json_request_ = request; }
bool DecryptApiResponse::HasJsonRequest() const { return json_request_.has_value(); }
const JsonRequest& DecryptApiResponse::GetJsonRequest() const { return json_request_.value(); }

DBPSApiClient::DBPSApiClient(const std::string& base_url)
    : http_client_(std::make_unique<HttplibClient>(base_url)) {
}

DBPSApiClient::DBPSApiClient(std::unique_ptr<HttpClientInterface> http_client)
    : http_client_(std::move(http_client)) {
}

std::string DBPSApiClient::HealthCheck() {
    auto response = http_client_->Get("/healthz");
    
    if (!response.error_message.empty()) {
        return "Error: " + response.error_message;
    }
    
    if (!IsHttpSuccess(response.status_code)) {
        return "Health check failed with status: " + std::to_string(response.status_code);
    }
    
    return response.result;
}

EncryptApiResponse DBPSApiClient::Encrypt(
    span<const uint8_t> plaintext,
    const std::string& column_name,
    Type::type datatype,
    CompressionCodec::type compression,
    Format::type format,
    CompressionCodec::type encrypted_compression,
    const std::string& key_id,
    const std::string& user_id
) {
    EncryptJsonRequest json_request;
    json_request.column_name_ = column_name;
    json_request.datatype_ = std::string(to_string(datatype));
    json_request.compression_ = std::string(to_string(compression));
    json_request.format_ = std::string(to_string(format));
    json_request.encrypted_compression_ = std::string(to_string(encrypted_compression));
    json_request.key_id_ = key_id;
    json_request.user_id_ = user_id;
    json_request.reference_id_ = GenerateReferenceId();

    // TODO: Add support for other formats and encodings.
    // Encode the plaintext as base64 and set the encoding param to BASE64.
    json_request.encoding_ = std::string(to_string(Encoding::BASE64));
    
    EncryptApiResponse api_response;
    try {
        // Encode the plaintext as base64 and set the value_ param.
        auto plaintext_b64 = EncodeBase64(plaintext);
        if (!plaintext_b64.has_value()) {
            api_response.SetApiClientError("Encrypt plaintext request - invalid base64 encoding");
            return api_response;
        }
        json_request.value_ = plaintext_b64.value();
        
        // Set the complete request after all fields are populated
        api_response.SetJsonRequest(json_request);

        // Check if only RAW_C_DATA format is implemented
        if (format != Format::RAW_C_DATA) {
            api_response.SetApiClientError("On request, only RAW_C_DATA format is currently implemented");
            return api_response;
        }

        // Check if the request is valid
        if (!json_request.IsValid()) {
            api_response.SetApiClientError("Invalid encrypt request");
            return api_response;
        }

        // Make the POST request
        auto http_response = http_client_->Post("/encrypt", json_request.ToJson());
        api_response.SetHttpStatusCode(http_response.status_code);

        // Check if the HTTP response has an error
        if (!http_response.error_message.empty() || !IsHttpSuccess(http_response.status_code)) {
            api_response.SetApiClientError("HTTP POST request failed for /encrypt: " + http_response.error_message);
            api_response.SetRawResponse(http_response.result);
            return api_response;
        }

        // Create an EncryptJsonResponse and parse since the HTTP response level succeeded.
        EncryptJsonResponse json_response;
        json_response.Parse(http_response.result);
        api_response.SetJsonResponse(json_response);

        // Check if the response is valid
        if (!json_response.IsValid()) {
            api_response.SetApiClientError("Invalid JSON encrypt response");
            api_response.SetRawResponse(http_response.result);
            return api_response;
        }

        // Check if the decoded ciphertext failed base64 decoding
        if (api_response.GetResponseCiphertext().empty()) {
            api_response.SetApiClientError("Decoded ciphertext response failed base64 decoding");
            api_response.SetRawResponse(http_response.result);
            return api_response;
        }

    } catch (const std::exception& e) {
        api_response.SetApiClientError("API client encrypt unexpected error: " + std::string(e.what()));
    }
    
    // Finally return the API response if all is good.
    return api_response;
}

DecryptApiResponse DBPSApiClient::Decrypt(
    span<const uint8_t> ciphertext,
    const std::string& column_name,
    Type::type datatype,
    CompressionCodec::type compression,
    Format::type format,
    CompressionCodec::type encrypted_compression,
    const std::string& key_id,
    const std::string& user_id
) {
    DecryptJsonRequest json_request;
    json_request.column_name_ = column_name;
    json_request.datatype_ = std::string(to_string(datatype));
    json_request.compression_ = std::string(to_string(compression));
    json_request.format_ = std::string(to_string(format));
    json_request.encrypted_compression_ = std::string(to_string(encrypted_compression));
    json_request.key_id_ = key_id;
    json_request.user_id_ = user_id;
    json_request.reference_id_ = GenerateReferenceId();

    // TODO: Add support for other formats and encodings.
    // Encode the ciphertext as base64 and set the encoding param to BASE64.
    json_request.encoding_ = std::string(to_string(Encoding::BASE64));
    
    DecryptApiResponse api_response;
    try {
        // Encode the ciphertext as base64 and set the encrypted_value_ param and 
        // check if it's valid before setting it.
        auto ciphertext_b64 = EncodeBase64(ciphertext);
        if (!ciphertext_b64.has_value()) {
            api_response.SetApiClientError("Decrypt ciphertext request  - invalid base64 encoding");
            return api_response;
        }
        json_request.encrypted_value_ = ciphertext_b64.value();
        
        // Set the complete request after all fields are populated
        api_response.SetJsonRequest(json_request);

        // Check if only RAW_C_DATA format is implemented
        if (format != Format::RAW_C_DATA) {
            api_response.SetApiClientError("On request, only RAW_C_DATA format is currently implemented");
            return api_response;
        }

        // Check if the request is valid
        if (!json_request.IsValid()) {
            api_response.SetApiClientError("Invalid decrypt request");
            return api_response;
        }

        // Make the POST request
        auto http_response = http_client_->Post("/decrypt", json_request.ToJson());
        api_response.SetHttpStatusCode(http_response.status_code);

        // Check if the HTTP response has an error
        if (!http_response.error_message.empty() || !IsHttpSuccess(http_response.status_code)) {
            api_response.SetApiClientError("HTTP POST request failed for /decrypt: " + http_response.error_message);
            api_response.SetRawResponse(http_response.result);
            return api_response;
        }

        // Create a DecryptJsonResponse and parse since the HTTP response level succeeded.
        DecryptJsonResponse json_response;
        json_response.Parse(http_response.result);
        api_response.SetJsonResponse(json_response);

        // Check if the response is valid
        if (!json_response.IsValid()) {
            api_response.SetApiClientError("Invalid JSON decrypt response");
            api_response.SetRawResponse(http_response.result);
            return api_response;
        }
        
        // Check if the decoded plaintext failed base64 decoding
        if (api_response.GetResponsePlaintext().empty()) {
            api_response.SetApiClientError("Decoded plaintext response failed base64 decoding");
            api_response.SetRawResponse(http_response.result);
            return api_response;
        }

    } catch (const std::exception& e) {
        api_response.SetApiClientError("API client decrypt unexpected error: " + std::string(e.what()));
    }
    
    return api_response;
}


