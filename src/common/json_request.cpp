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

#include "json_request.h"
#include <crow/app.h>
#include <sstream>
#include <nlohmann/json.hpp>
#include <cppcodec/base64_rfc4648.hpp>

using namespace dbps::enum_utils;

/**
* Safely extracts a string value from a nested JSON path.
*
* Traverses a JSON object following a specified path and returns
* the string value at the end of the path. If any part of the path doesn't exist
* or if an exception occurs during traversal, it returns std::nullopt.
*
* @param json_body The JSON object to traverse
* @param path Vector of strings representing the path to traverse
* @return std::optional<std::string> containing the value if found, std::nullopt otherwise
*/
std::optional<std::string> SafeGetFromJsonPath(const crow::json::rvalue& json_body, const std::vector<std::string>& path) {
    try {
        // Check if json_body is empty or null.
        // !json_body is an oveloaded operator that checks if the json_body parsing failed.
        if (!json_body || json_body.t() == crow::json::type::Null) {
            return std::nullopt;
        }
        
        const crow::json::rvalue* current = &json_body;
        for (const auto& field : path) {
            if (!current->has(field)) {
                return std::nullopt;
            }
            current = &((*current)[field]);
        }
        return std::string(*current); // Converts any JSON type to string
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Exception in SafeGetFromJsonPath: " << e.what();
        return std::nullopt;
    }
}

// Helper function to safely parse a string to integer
std::optional<int> SafeParseToInt(const std::string& str) {
    try {
        return std::stoi(str);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// Helper function to safely load JSON body and return nullopt if invalid or null
static std::optional<crow::json::rvalue> SafeLoadJsonBody(const std::string& json_string) {
    auto json_body = crow::json::load(json_string);
    if (!json_body || json_body.t() == crow::json::type::Null) {
        CROW_LOG_ERROR << "Invalid JSON body: " << json_string;
        return std::nullopt;
    }
    return json_body;
}

// Helper function to build validation error message from missing fields
static std::string BuildValidationError(const std::vector<std::string>& missing_fields) {
    if (missing_fields.empty()) {
        return "";
    }
    std::ostringstream oss;
    oss << "Missing required fields: ";
    for (size_t i = 0; i < missing_fields.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << missing_fields[i];
    }
    return oss.str();
}

// Pretty prints a JSON string with 4-space indentation using nlohmann JSON.
// If the input is not valid JSON, returns the original string.
std::string PrettyPrintJson(const std::string& json_str) {
    try {
        nlohmann::json j = nlohmann::json::parse(json_str);
        return j.dump(4);
    } catch (const nlohmann::json::exception& e) {
        // If parsing fails, return the original string
        return json_str;
    }
}

/**
 * Safely decodes a base64 string to binary data.
 * @param base64_string The base64 encoded string
 * @return std::optional<std::vector<uint8_t>> containing the decoded data, std::nullopt if decoding fails
 */
std::optional<std::vector<uint8_t>> DecodeBase64Safe(const std::string& base64_string) {
    try {
        return cppcodec::base64_rfc4648::decode(base64_string);
    } catch (const std::exception& e) {
        // Return nullopt on decoding failure
        return std::nullopt;
    }
}

/**
 * Safely encodes binary data to a base64 string.
 * @param data The binary data to encode
 * @return std::string containing the base64 encoded data
 */
std::string EncodeBase64Safe(const std::vector<uint8_t>& data) {
    try {
        return cppcodec::base64_rfc4648::encode(data);
    } catch (const std::exception& e) {
        // Return empty string on encoding failure
        return std::string();
    }
}

void TokenRequest::Parse(const std::string& request_body) {
    client_id_.clear();
    api_key_.clear();

    auto json_body_opt = SafeLoadJsonBody(request_body);
    if (!json_body_opt) {
        return;
    }

    auto json_body = *json_body_opt;
    if (json_body.t() != crow::json::type::Object) {
        return;
    }

    if (json_body.has("client_id") && json_body["client_id"].t() == crow::json::type::String) {
        client_id_ = std::string(json_body["client_id"]);
    } else {
        return;
    }

    if (json_body.has("api_key") && json_body["api_key"].t() == crow::json::type::String) {
        api_key_ = std::string(json_body["api_key"]);
    } else {
        return;
    }
}

std::string TokenRequest::ToJson() const {
    crow::json::wvalue json;
    if (!IsValid()) {
        json["error"] = GetValidationError();
        return PrettyPrintJson(json.dump());
    }

    json["client_id"] = client_id_;
    json["api_key"] = api_key_;
    return PrettyPrintJson(json.dump());
}

bool TokenRequest::IsValid() const {
    return !client_id_.empty() && !api_key_.empty();
}

std::string TokenRequest::GetValidationError() const {
    if (IsValid()) {
        return "";
    }
    std::vector<std::string> missing_fields;
    if (client_id_.empty()) missing_fields.push_back("client_id");
    if (api_key_.empty()) missing_fields.push_back("api_key");
    return BuildValidationError(missing_fields);
}

void TokenResponse::Parse(const std::string& response_body) {
    token_ = std::nullopt;
    expires_at_ = std::nullopt;
    error_message_.clear();
    error_status_code_ = 0;

    auto json_body_opt = SafeLoadJsonBody(response_body);
    if (!json_body_opt) {
        return;
    }

    auto json_body = *json_body_opt;
    if (json_body.t() != crow::json::type::Object) {
        return;
    }

    if (json_body.has("error")) {
        error_message_ = std::string(json_body["error"]);
        return;
    }

    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"token"})) {
        token_ = *parsed_value;
    }

    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"expires_at"})) {
        try {
            expires_at_ = std::stoll(*parsed_value);
        } catch (const std::exception&) {
            return;
        }
    }
}

bool TokenResponse::IsValid() const {
    return error_message_.empty() &&
           token_.has_value() &&
           !token_.value().empty() &&
           expires_at_.has_value();
}

std::string TokenResponse::GetValidationError() const {
    if (error_status_code_ == 401) {
        return "Invalid credentials";
    }
    if (!error_message_.empty()) {
        return error_message_;
    }
    if (IsValid()) {
        return "";
    }
    std::vector<std::string> missing_fields;
    if (!token_.has_value() || token_.value().empty()) missing_fields.push_back("token");
    if (!expires_at_.has_value()) missing_fields.push_back("expires_at");
    return BuildValidationError(missing_fields);
}

void TokenResponse::SetErrorStatusCodeAndClearToken(int status_code) {
    token_ = std::nullopt;
    expires_at_ = std::nullopt;
    error_message_.clear();
    error_status_code_ = status_code;
}

std::string TokenResponse::ToJson() const {
    crow::json::wvalue json;

    if (!IsValid()) {
        json["error"] = GetValidationError();
        return json.dump();
    }

    json["token"] = token_.value();
    json["token_type"] = "Bearer";
    json["expires_at"] = expires_at_.value();

    return PrettyPrintJson(json.dump());
}

// JsonRequest implementation
void JsonRequest::ParseCommon(const std::string& request_body) {
    // Load and validate JSON first
    auto json_body_opt = SafeLoadJsonBody(request_body);
    if (!json_body_opt) return; // Stop parsing if JSON is invalid
    auto json_body = *json_body_opt;
    
    // Extract common required fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"column_reference", "name"})) {
        column_name_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "datatype_info", "datatype"})) {
        if (auto enum_value = to_datatype_enum(*parsed_value)) {
            datatype_ = *enum_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "datatype_info", "length"})) {
        // Parse as integer when the parsed_value is not empty
        if (auto int_value = SafeParseToInt(*parsed_value)) {
            datatype_length_ = *int_value;
        } else {
            // If integer parsing fails, capture the parsed value for validation check
            datatype_length_str_ = *parsed_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "compression"})) {
        if (auto enum_value = to_compression_enum(*parsed_value)) {
            compression_ = *enum_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "format"})) {
        if (auto enum_value = to_format_enum(*parsed_value)) {
            format_ = *enum_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value_format", "compression"})) {
        if (auto enum_value = to_compression_enum(*parsed_value)) {
            encrypted_compression_ = *enum_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"encryption", "key_id"})) {
        key_id_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"access", "user_id"})) {
        user_id_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"application_context"})) {
        application_context_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"debug", "reference_id"})) {
        reference_id_ = *parsed_value;
    }
    
    // Extract encoding_attributes
    if (json_body.has("data_batch") && json_body["data_batch"].has("value_format") && 
        json_body["data_batch"]["value_format"].has("encoding_attributes")) {
        auto attrs_json = json_body["data_batch"]["value_format"]["encoding_attributes"];
        // Check that attrs_json is not empty and is not an array or literal value
        if (attrs_json && attrs_json.t() == crow::json::type::Object) {
            auto keys = attrs_json.keys();
            for (const auto& key : keys) {
                encoding_attributes_[key] = std::string(attrs_json[key]);
            }
        }
    }
}

bool JsonRequest::IsValid() const {
    // Check if datatype_length_str_ is not empty, then it must be parseable as integer
    bool datatype_length_valid = true;
    if (!datatype_length_str_.empty()) {
        datatype_length_valid = SafeParseToInt(datatype_length_str_).has_value();
    }
    
    return !column_name_.empty() && 
           datatype_.has_value() && 
           compression_.has_value() && 
           format_.has_value() && 
           encrypted_compression_.has_value() && 
           !key_id_.empty() && 
           !user_id_.empty() && 
           !application_context_.empty() && 
           !reference_id_.empty() &&
           datatype_length_valid;
}

std::string JsonRequest::GetValidationError() const {
    std::vector<std::string> missing_fields;
    
    if (column_name_.empty()) missing_fields.push_back("column_reference.name");
    if (!datatype_.has_value()) missing_fields.push_back("data_batch.datatype_info.datatype");
    if (!compression_.has_value()) missing_fields.push_back("data_batch.value_format.compression");
    if (!format_.has_value()) missing_fields.push_back("data_batch.value_format.format");
    if (!encrypted_compression_.has_value()) missing_fields.push_back("data_batch_encrypted.value_format.compression");
    if (key_id_.empty()) missing_fields.push_back("encryption.key_id");
    if (user_id_.empty()) missing_fields.push_back("access.user_id");
    if (application_context_.empty()) missing_fields.push_back("application_context");
    if (reference_id_.empty()) missing_fields.push_back("debug.reference_id");
    
    // Check for invalid datatype_length
    if (!datatype_length_str_.empty() && !SafeParseToInt(datatype_length_str_).has_value()) {
        missing_fields.push_back("data_batch.datatype_info.length (invalid integer value)");
    }
    
    return BuildValidationError(missing_fields);
}

std::string JsonRequest::ToJson() const {
    if (!IsValid()) {
        // Return a fixed error JSON indicating invalid state
        crow::json::wvalue error_json;
        error_json["error"] = "Invalid JSON request";
        error_json["details"] = GetValidationError();
        return error_json.dump();
    }
    return ToJsonString();
}

// EncryptJsonRequest implementation
void EncryptJsonRequest::Parse(const std::string& request_body) {
    // Parse common fields first
    ParseCommon(request_body);
    
    // Load JSON for encrypt-specific fields
    auto json_body_opt = SafeLoadJsonBody(request_body);
    if (!json_body_opt) return;
    auto json_body = *json_body_opt;
    
    // Extract encrypt-specific fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value"})) {
        if (auto decoded_value = DecodeBase64Safe(*parsed_value)) {
            value_ = *decoded_value;
        }
    }
}

bool EncryptJsonRequest::IsValid() const {
    return JsonRequest::IsValid() && !value_.empty();
}

std::string EncryptJsonRequest::GetValidationError() const {
    std::string base_error = JsonRequest::GetValidationError();
    if (!base_error.empty()) {
        return base_error;
    }
    
    if (value_.empty()) {
        return "Missing required field: data_batch.value";
    }
    
    return "";
}

std::string EncryptJsonRequest::ToJsonString() const {
    crow::json::wvalue json;
    
    // Build column_reference
    crow::json::wvalue column_reference;
    column_reference["name"] = column_name_;
    json["column_reference"] = std::move(column_reference);
    
    // Build data_batch
    crow::json::wvalue data_batch;
    
    // Build datatype_info inside data_batch
    crow::json::wvalue datatype_info;
    datatype_info["datatype"] = std::string(to_string(datatype_.value()));
    if (datatype_length_.has_value()) {
        datatype_info["length"] = datatype_length_.value();
    }
    data_batch["datatype_info"] = std::move(datatype_info);
    
    data_batch["value"] = EncodeBase64Safe(value_);
    
    crow::json::wvalue value_format;
    value_format["compression"] = std::string(to_string(compression_.value()));
    value_format["format"] = std::string(to_string(format_.value()));
    
    // Add encoding_attributes if not empty
    if (!encoding_attributes_.empty()) {
        crow::json::wvalue encoding_attrs;
        for (const auto& pair : encoding_attributes_) {
            encoding_attrs[pair.first] = pair.second;
        }
        value_format["encoding_attributes"] = std::move(encoding_attrs);
    }
    
    data_batch["value_format"] = std::move(value_format);
    
    json["data_batch"] = std::move(data_batch);
    
    // Build data_batch_encrypted
    crow::json::wvalue data_batch_encrypted;
    crow::json::wvalue encrypted_value_format;
    encrypted_value_format["compression"] = std::string(to_string(encrypted_compression_.value()));
    data_batch_encrypted["value_format"] = std::move(encrypted_value_format);
    json["data_batch_encrypted"] = std::move(data_batch_encrypted);
    
    // Build encryption
    crow::json::wvalue encryption;
    encryption["key_id"] = key_id_;
    json["encryption"] = std::move(encryption);
    
    // Build access
    crow::json::wvalue access;
    access["user_id"] = user_id_;
    json["access"] = std::move(access);
    json["application_context"] = application_context_;
    
    // Build debug
    crow::json::wvalue debug;
    debug["reference_id"] = reference_id_;
    json["debug"] = std::move(debug);
    
    // Converts crow json object to a string with pretty printing
    return PrettyPrintJson(json.dump());
}

// DecryptJsonRequest implementation
void DecryptJsonRequest::Parse(const std::string& request_body) {
    // Parse common fields first
    ParseCommon(request_body);
    
    // Load JSON for decrypt-specific fields
    auto json_body_opt = SafeLoadJsonBody(request_body);
    if (!json_body_opt) return;
    auto json_body = *json_body_opt;
    
    // Extract decrypt-specific fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value"})) {
        if (auto decoded_value = DecodeBase64Safe(*parsed_value)) {
            encrypted_value_ = *decoded_value;
        }
    }

    if (json_body.has("encryption_metadata") && json_body["encryption_metadata"].t() == crow::json::type::Object) {
        auto metadata = json_body["encryption_metadata"];
        auto keys = metadata.keys();
        for (const auto& key : keys) {
            encryption_metadata_[key] = std::string(metadata[key]);
        }
    }
}

bool DecryptJsonRequest::IsValid() const {
    return JsonRequest::IsValid() && !encrypted_value_.empty();
}

std::string DecryptJsonRequest::GetValidationError() const {
    std::string base_error = JsonRequest::GetValidationError();
    if (!base_error.empty()) {
        return base_error;
    }
    
    if (encrypted_value_.empty()) {
        return "Missing required field: data_batch_encrypted.value";
    }
    
    return "";
}

std::string DecryptJsonRequest::ToJsonString() const {
    crow::json::wvalue json;
    
    // Build column_reference
    crow::json::wvalue column_reference;
    column_reference["name"] = column_name_;
    json["column_reference"] = std::move(column_reference);
    
    // Build data_batch
    crow::json::wvalue data_batch;
    
    // Build datatype_info inside data_batch
    crow::json::wvalue datatype_info;
    datatype_info["datatype"] = std::string(to_string(datatype_.value()));
    if (datatype_length_.has_value()) {
        datatype_info["length"] = datatype_length_.value();
    }
    data_batch["datatype_info"] = std::move(datatype_info);
    
    crow::json::wvalue value_format;
    value_format["compression"] = std::string(to_string(compression_.value()));
    value_format["format"] = std::string(to_string(format_.value()));
    
    // Add encoding_attributes if not empty
    if (!encoding_attributes_.empty()) {
        crow::json::wvalue encoding_attrs;
        for (const auto& pair : encoding_attributes_) {
            encoding_attrs[pair.first] = pair.second;
        }
        value_format["encoding_attributes"] = std::move(encoding_attrs);
    }
    
    data_batch["value_format"] = std::move(value_format);
    
    json["data_batch"] = std::move(data_batch);
    
    // Build data_batch_encrypted
    crow::json::wvalue data_batch_encrypted;
    data_batch_encrypted["value"] = EncodeBase64Safe(encrypted_value_);
    
    crow::json::wvalue encrypted_value_format;
    encrypted_value_format["compression"] = std::string(to_string(encrypted_compression_.value()));
    data_batch_encrypted["value_format"] = std::move(encrypted_value_format);
    json["data_batch_encrypted"] = std::move(data_batch_encrypted);
    
    // Build encryption
    crow::json::wvalue encryption;
    encryption["key_id"] = key_id_;
    json["encryption"] = std::move(encryption);
    
    // Build access
    crow::json::wvalue access;
    access["user_id"] = user_id_;
    json["access"] = std::move(access);
    json["application_context"] = application_context_;
    
    // Build debug
    crow::json::wvalue debug;
    debug["reference_id"] = reference_id_;
    json["debug"] = std::move(debug);

    // If the encryption_metadata is empty, create an empty object.
    if (!encryption_metadata_.empty()) {
        crow::json::wvalue metadata;
        for (const auto& pair : encryption_metadata_) {
            metadata[pair.first] = pair.second;
        }
        json["encryption_metadata"] = std::move(metadata);
    } else {
        json["encryption_metadata"] = crow::json::load("{}");
    }

    // Converts crow json object to a string with pretty printing
    return PrettyPrintJson(json.dump());
}

// JsonResponse implementations
void JsonResponse::Parse(const std::string& response_body) {
    // Load and validate JSON first
    auto json_body_opt = SafeLoadJsonBody(response_body);
    if (!json_body_opt) return; // Stop parsing if JSON is invalid
    auto json_body = *json_body_opt;
    
    // Extract common required fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"access", "user_id"})) {
        user_id_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"access", "role"})) {
        role_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"access", "access_control"})) {
        access_control_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"debug", "reference_id"})) {
        reference_id_ = *parsed_value;
    }
}

void EncryptJsonResponse::Parse(const std::string& response_body) {
    // Parse common fields first
    JsonResponse::Parse(response_body);
    
    // Load JSON for encrypt-specific fields
    auto json_body_opt = SafeLoadJsonBody(response_body);
    if (!json_body_opt) return;
    auto json_body = *json_body_opt;

    // Extract encrypt-specific fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value_format", "compression"})) {
        if (auto enum_value = to_compression_enum(*parsed_value)) {
            encrypted_compression_ = *enum_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value"})) {
        if (auto decoded_value = DecodeBase64Safe(*parsed_value)) {
            encrypted_value_ = *decoded_value;
        }
    }
    
    // Parse encryption_metadata if it exists
    if (json_body.has("encryption_metadata") && json_body["encryption_metadata"].t() == crow::json::type::Object) {
        auto metadata = json_body["encryption_metadata"];
        auto keys = metadata.keys();
        for (const auto& key : keys) {
            encryption_metadata_[key] = std::string(metadata[key]);
        }
    }
}

void DecryptJsonResponse::Parse(const std::string& response_body) {
    // Parse common fields first
    JsonResponse::Parse(response_body);
    
    // Load JSON for decrypt-specific fields
    auto json_body_opt = SafeLoadJsonBody(response_body);
    if (!json_body_opt) return;
    auto json_body = *json_body_opt;
    
    // Extract decrypt-specific fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "datatype_info", "datatype"})) {
        if (auto enum_value = to_datatype_enum(*parsed_value)) {
            datatype_ = *enum_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "datatype_info", "length"})) {
        // Parse as integer when the parsed_value is not empty
        if (auto int_value = SafeParseToInt(*parsed_value)) {
            datatype_length_ = *int_value;
        } else {
            // If integer parsing fails, capture the parsed value for validation check
            datatype_length_str_ = *parsed_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "compression"})) {
        if (auto enum_value = to_compression_enum(*parsed_value)) {
            compression_ = *enum_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "format"})) {
        if (auto enum_value = to_format_enum(*parsed_value)) {
            format_ = *enum_value;
        }
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value"})) {
        if (auto decoded_value = DecodeBase64Safe(*parsed_value)) {
            decrypted_value_ = *decoded_value;
        }
    }
}

bool JsonResponse::IsValid() const {
    return !user_id_.empty() && 
           !role_.empty() && 
           !access_control_.empty() && 
           !reference_id_.empty();
}

std::string JsonResponse::GetValidationError() const {
    std::vector<std::string> missing_fields;
    
    if (user_id_.empty()) missing_fields.push_back("access.user_id");
    if (role_.empty()) missing_fields.push_back("access.role");
    if (access_control_.empty()) missing_fields.push_back("access.access_control");
    if (reference_id_.empty()) missing_fields.push_back("debug.reference_id");
    
    return BuildValidationError(missing_fields);
}

std::string JsonResponse::ToJson() const {
    if (!IsValid()) {
        // Return a fixed error JSON indicating invalid state
        crow::json::wvalue error_json;
        error_json["error"] = "Invalid JSON response";
        error_json["details"] = GetValidationError();
        return error_json.dump();
    }
    return ToJsonString();
}

bool EncryptJsonResponse::IsValid() const {
    return JsonResponse::IsValid() && 
           encrypted_compression_.has_value() && 
           !encrypted_value_.empty();
}

std::string EncryptJsonResponse::GetValidationError() const {
    std::vector<std::string> missing_fields;
    
    // Check base class fields
    if (user_id_.empty()) missing_fields.push_back("access.user_id");
    if (role_.empty()) missing_fields.push_back("access.role");
    if (access_control_.empty()) missing_fields.push_back("access.access_control");
    if (reference_id_.empty()) missing_fields.push_back("debug.reference_id");
    
    // Check encrypt-specific fields
    if (!encrypted_compression_.has_value()) missing_fields.push_back("data_batch_encrypted.value_format.compression");
    if (encrypted_value_.empty()) missing_fields.push_back("data_batch_encrypted.value");
    
    return BuildValidationError(missing_fields);
}

std::string EncryptJsonResponse::ToJsonString() const {
    crow::json::wvalue json;
    
    // Build data_batch_encrypted
    crow::json::wvalue data_batch_encrypted;
    crow::json::wvalue encrypted_value_format;
    encrypted_value_format["compression"] = std::string(to_string(encrypted_compression_.value()));
    data_batch_encrypted["value_format"] = std::move(encrypted_value_format);
    data_batch_encrypted["value"] = EncodeBase64Safe(encrypted_value_);
    json["data_batch_encrypted"] = std::move(data_batch_encrypted);
    
    // Build access
    crow::json::wvalue access;
    access["user_id"] = user_id_;
    access["role"] = role_;
    access["access_control"] = access_control_;
    json["access"] = std::move(access);
    
    // Build debug
    crow::json::wvalue debug;
    debug["reference_id"] = reference_id_;
    json["debug"] = std::move(debug);
    
    // If the encryption_metadata is empty, create an empty object.
    if (!encryption_metadata_.empty()) {
        crow::json::wvalue metadata;
        for (const auto& pair : encryption_metadata_) {
            metadata[pair.first] = pair.second;
        }
        json["encryption_metadata"] = std::move(metadata);
    } else {
        json["encryption_metadata"] = crow::json::load("{}");
    }
    
    // Converts crow json object to a string with pretty printing
    return PrettyPrintJson(json.dump());
}

bool DecryptJsonResponse::IsValid() const {
    // Check if datatype_length_str_ is not empty, then it must be parseable as integer
    bool datatype_length_valid = true;
    if (!datatype_length_str_.empty()) {
        datatype_length_valid = SafeParseToInt(datatype_length_str_).has_value();
    }
    
    return JsonResponse::IsValid() && 
           datatype_.has_value() && 
           compression_.has_value() && 
           format_.has_value() && 
           !decrypted_value_.empty() &&
           datatype_length_valid;
}

std::string DecryptJsonResponse::GetValidationError() const {
    std::vector<std::string> missing_fields;
    
    // Check base class fields
    if (user_id_.empty()) missing_fields.push_back("access.user_id");
    if (role_.empty()) missing_fields.push_back("access.role");
    if (access_control_.empty()) missing_fields.push_back("access.access_control");
    if (reference_id_.empty()) missing_fields.push_back("debug.reference_id");
    
    // Check decrypt-specific fields
    if (!datatype_.has_value()) missing_fields.push_back("data_batch.datatype_info.datatype");
    if (!compression_.has_value()) missing_fields.push_back("data_batch.value_format.compression");
    if (!format_.has_value()) missing_fields.push_back("data_batch.value_format.format");
    if (decrypted_value_.empty()) missing_fields.push_back("data_batch.value");
    
    // Check for invalid datatype_length
    if (!datatype_length_str_.empty() && !SafeParseToInt(datatype_length_str_).has_value()) {
        missing_fields.push_back("data_batch.datatype_info.length (invalid integer value)");
    }
    
    return BuildValidationError(missing_fields);
}

std::string DecryptJsonResponse::ToJsonString() const {
    crow::json::wvalue json;
    
    // Build data_batch
    crow::json::wvalue data_batch;
    
    // Build datatype_info inside data_batch
    crow::json::wvalue datatype_info;
    datatype_info["datatype"] = std::string(to_string(datatype_.value()));
    if (datatype_length_.has_value()) {
        datatype_info["length"] = datatype_length_.value();
    }
    data_batch["datatype_info"] = std::move(datatype_info);
    
    data_batch["value"] = EncodeBase64Safe(decrypted_value_);
    
    crow::json::wvalue value_format;
    value_format["compression"] = std::string(to_string(compression_.value()));
    value_format["format"] = std::string(to_string(format_.value()));
    data_batch["value_format"] = std::move(value_format);
    
    json["data_batch"] = std::move(data_batch);
    
    // Build access
    crow::json::wvalue access;
    access["user_id"] = user_id_;
    access["role"] = role_;
    access["access_control"] = access_control_;
    json["access"] = std::move(access);
    
    // Build debug
    crow::json::wvalue debug;
    debug["reference_id"] = reference_id_;
    json["debug"] = std::move(debug);
    
    // Converts crow json object to a string with pretty printing
    return PrettyPrintJson(json.dump());
}
