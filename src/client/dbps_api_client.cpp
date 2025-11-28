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

// Project includes
#include "dbps_api_client.h"
#include "httplib_client.h"

// Standard library includes
#include <sstream>
#include <stdexcept>
#include <chrono>

using namespace dbps::external;
using namespace dbps::enum_utils;

// Generate a simple unique reference ID using timestamp
// TODO: Potentially not-unique if concurrent calls are made on the same millisecond.
//       Can use atomic counters but may not be an issue to justify the complexity.
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
    if (HasApiClientError()) return "API client error: " + GetApiClientError();
    if (!HasHttpStatusCode()) return "No HTTP status code";
    if (!IsHttpSuccess(GetHttpStatusCode())) return "Non-2xx HTTP status code: " + std::to_string(GetHttpStatusCode());
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
        decoded_ciphertext_ = response.encrypted_value_;
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
        decoded_plaintext_ = response.decrypted_value_;
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

DBPSApiClient::DBPSApiClient(std::shared_ptr<HttpClientInterface> http_client)
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
    const std::optional<int>& datatype_length,
    CompressionCodec::type compression,
    Format::type format,
    const std::map<std::string, std::string>& encoding_attributes,
    CompressionCodec::type encrypted_compression,
    const std::string& key_id,
    const std::string& user_id,
    const std::string& application_context
) {
    EncryptJsonRequest json_request;
    json_request.column_name_ = column_name;
    json_request.datatype_ = datatype;
    json_request.datatype_length_ = datatype_length;
    json_request.compression_ = compression;
    json_request.format_ = format;
    json_request.encoding_attributes_ = encoding_attributes;
    json_request.encrypted_compression_ = encrypted_compression;
    json_request.key_id_ = key_id;
    json_request.user_id_ = user_id;
    json_request.application_context_ = application_context;
    json_request.reference_id_ = GenerateReferenceId();

    EncryptApiResponse api_response;
    try {
        // Set the binary plaintext data directly (base64 conversion handled on json request functions)
        json_request.value_ = std::vector<uint8_t>(plaintext.begin(), plaintext.end());
        
        // Set the complete request after all fields are populated
        api_response.SetJsonRequest(json_request);

        // Check if the request is valid
        if (!json_request.IsValid()) {
            api_response.SetApiClientError("Invalid encrypt request");
            return api_response;
        }

        // Make the POST request
        auto http_response = http_client_->Post("/encrypt", json_request.ToJson());
        api_response.SetHttpStatusCode(http_response.status_code);

        // Check if the HTTP response has an error and include the server response body when available
        if (!http_response.error_message.empty() || !IsHttpSuccess(http_response.status_code)) {
            std::string error_msg = "HTTP POST request failed for /encrypt: [" + std::to_string(http_response.status_code) + "] [" + http_response.error_message + "]";
            if (!http_response.result.empty()) {
                error_msg += " Server response: " + http_response.result;
            }
            api_response.SetApiClientError(error_msg);
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

        // Check if the decoded ciphertext is empty
        if (api_response.GetResponseCiphertext().empty()) {
            api_response.SetApiClientError("Decoded ciphertext response is empty");
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
    const std::optional<int>& datatype_length,
    CompressionCodec::type compression,
    Format::type format,
    const std::map<std::string, std::string>& encoding_attributes,
    CompressionCodec::type encrypted_compression,
    const std::string& key_id,
    const std::string& user_id,
    const std::string& application_context,
    const std::map<std::string, std::string>& encryption_metadata
) {
    DecryptJsonRequest json_request;
    json_request.column_name_ = column_name;
    json_request.datatype_ = datatype;
    json_request.datatype_length_ = datatype_length;
    json_request.compression_ = compression;
    json_request.format_ = format;
    json_request.encoding_attributes_ = encoding_attributes;
    json_request.encrypted_compression_ = encrypted_compression;
    json_request.key_id_ = key_id;
    json_request.user_id_ = user_id;
    json_request.application_context_ = application_context;
    json_request.encryption_metadata_ = encryption_metadata;
    json_request.reference_id_ = GenerateReferenceId();

    DecryptApiResponse api_response;
    try {
        // Set the binary ciphertext data directly (base64 conversion handled on json request functions)
        json_request.encrypted_value_ = std::vector<uint8_t>(ciphertext.begin(), ciphertext.end());
        
        // Set the complete request after all fields are populated
        api_response.SetJsonRequest(json_request);

        // Check if the request is valid
        if (!json_request.IsValid()) {
            api_response.SetApiClientError("Invalid decrypt request");
            return api_response;
        }

        // Make the POST request
        auto http_response = http_client_->Post("/decrypt", json_request.ToJson());
        api_response.SetHttpStatusCode(http_response.status_code);

        // Check if the HTTP response has an error and include the server response body when available
        if (!http_response.error_message.empty() || !IsHttpSuccess(http_response.status_code)) {
            std::string error_msg = "HTTP POST request failed for /decrypt: [" + std::to_string(http_response.status_code) + "] [" + http_response.error_message + "]";
            if (!http_response.result.empty()) {
                error_msg += " Server response: " + http_response.result;
            }
            api_response.SetApiClientError(error_msg);
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
        
        // Check if the decoded plaintext is empty
        if (api_response.GetResponsePlaintext().empty()) {
            api_response.SetApiClientError("Decoded plaintext response is empty");
            api_response.SetRawResponse(http_response.result);
            return api_response;
        }

    } catch (const std::exception& e) {
        api_response.SetApiClientError("API client decrypt unexpected error: " + std::string(e.what()));
    }
    
    return api_response;
}
