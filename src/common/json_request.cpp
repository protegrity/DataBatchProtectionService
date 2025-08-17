#include "json_request.h"
#include <sstream>

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

// Utility function to safely extract a string value from a nested JSON path
std::optional<std::string> SafeGetFromJsonPath(const crow::json::rvalue& json_body, const std::vector<std::string>& path) {
    try {
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

// JsonRequest implementation
void JsonRequest::ParseCommon(const std::string& request_body) {
    // Load and validate JSON first
    auto json_body = crow::json::load(request_body);
    
    if (!json_body) return; // Stop parsing if JSON is invalid
    
    // Extract common required fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"column_reference", "name"})) {
        column_name_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "datatype"})) {
        datatype_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "compression"})) {
        compression_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "format"})) {
        format_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "encoding"})) {
        encoding_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value_format", "compression"})) {
        encrypted_compression_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"encryption", "key_id"})) {
        key_id_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"access", "user_id"})) {
        user_id_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"debug", "reference_id"})) {
        reference_id_ = *parsed_value;
    }
}

bool JsonRequest::IsValid() const {
    return !column_name_.empty() && 
           !datatype_.empty() && 
           !compression_.empty() && 
           !format_.empty() && 
           !encoding_.empty() && 
           !encrypted_compression_.empty() && 
           !key_id_.empty() && 
           !user_id_.empty() && 
           !reference_id_.empty();
}

std::string JsonRequest::GetValidationError() const {
    std::vector<std::string> missing_fields;
    
    if (column_name_.empty()) missing_fields.push_back("column_reference.name");
    if (datatype_.empty()) missing_fields.push_back("data_batch.datatype");
    if (compression_.empty()) missing_fields.push_back("data_batch.value_format.compression");
    if (format_.empty()) missing_fields.push_back("data_batch.value_format.format");
    if (encoding_.empty()) missing_fields.push_back("data_batch.value_format.encoding");
    if (encrypted_compression_.empty()) missing_fields.push_back("data_batch_encrypted.value_format.compression");
    if (key_id_.empty()) missing_fields.push_back("encryption.key_id");
    if (user_id_.empty()) missing_fields.push_back("access.user_id");
    if (reference_id_.empty()) missing_fields.push_back("debug.reference_id");
    
    return BuildValidationError(missing_fields);
}

std::string JsonRequest::ToJson() const {
    return ToJsonObject().dump();
}

// EncryptJsonRequest implementation
void EncryptJsonRequest::Parse(const std::string& request_body) {
    // Parse common fields first
    ParseCommon(request_body);
    
    // Load JSON for encrypt-specific fields
    auto json_body = crow::json::load(request_body);
    if (!json_body) return;
    
    // Extract encrypt-specific fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value"})) {
        value_ = *parsed_value;
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

crow::json::wvalue EncryptJsonRequest::ToJsonObject() const {
    crow::json::wvalue json;
    
    // Build column_reference
    crow::json::wvalue column_reference;
    column_reference["name"] = column_name_;
    json["column_reference"] = std::move(column_reference);
    
    // Build data_batch
    crow::json::wvalue data_batch;
    data_batch["datatype"] = datatype_;
    data_batch["value"] = value_;
    
    crow::json::wvalue value_format;
    value_format["compression"] = compression_;
    value_format["format"] = format_;
    value_format["encoding"] = encoding_;
    data_batch["value_format"] = std::move(value_format);
    
    json["data_batch"] = std::move(data_batch);
    
    // Build data_batch_encrypted
    crow::json::wvalue data_batch_encrypted;
    crow::json::wvalue encrypted_value_format;
    encrypted_value_format["compression"] = encrypted_compression_;
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
    
    // Build debug
    crow::json::wvalue debug;
    debug["reference_id"] = reference_id_;
    json["debug"] = std::move(debug);
    
    return json;
}

// DecryptJsonRequest implementation
void DecryptJsonRequest::Parse(const std::string& request_body) {
    // Parse common fields first
    ParseCommon(request_body);
    
    // Load JSON for decrypt-specific fields
    auto json_body = crow::json::load(request_body);
    if (!json_body) return;
    
    // Extract decrypt-specific fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value"})) {
        encrypted_value_ = *parsed_value;
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

crow::json::wvalue DecryptJsonRequest::ToJsonObject() const {
    crow::json::wvalue json;
    
    // Build column_reference
    crow::json::wvalue column_reference;
    column_reference["name"] = column_name_;
    json["column_reference"] = std::move(column_reference);
    
    // Build data_batch
    crow::json::wvalue data_batch;
    data_batch["datatype"] = datatype_;
    
    crow::json::wvalue value_format;
    value_format["compression"] = compression_;
    value_format["format"] = format_;
    value_format["encoding"] = encoding_;
    data_batch["value_format"] = std::move(value_format);
    
    json["data_batch"] = std::move(data_batch);
    
    // Build data_batch_encrypted
    crow::json::wvalue data_batch_encrypted;
    data_batch_encrypted["value"] = encrypted_value_;
    
    crow::json::wvalue encrypted_value_format;
    encrypted_value_format["compression"] = encrypted_compression_;
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
    
    // Build debug
    crow::json::wvalue debug;
    debug["reference_id"] = reference_id_;
    json["debug"] = std::move(debug);
    
    return json;
}

// JsonResponse implementations
void JsonResponse::Parse(const std::string& response_body) {
    // Load and validate JSON first
    auto json_body = crow::json::load(response_body);
    
    if (!json_body) return; // Stop parsing if JSON is invalid
    
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
    auto json_body = crow::json::load(response_body);
    if (!json_body) return;
    
    // Extract encrypt-specific fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value_format", "compression"})) {
        encrypted_compression_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value"})) {
        encrypted_value_ = *parsed_value;
    }
}

void DecryptJsonResponse::Parse(const std::string& response_body) {
    // Parse common fields first
    JsonResponse::Parse(response_body);
    
    // Load JSON for decrypt-specific fields
    auto json_body = crow::json::load(response_body);
    if (!json_body) return;
    
    // Extract decrypt-specific fields
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "datatype"})) {
        datatype_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "compression"})) {
        compression_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "format"})) {
        format_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "encoding"})) {
        encoding_ = *parsed_value;
    }
    if (auto parsed_value = SafeGetFromJsonPath(json_body, {"data_batch", "value"})) {
        decrypted_value_ = *parsed_value;
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
    return ToJsonObject().dump();
}

bool EncryptJsonResponse::IsValid() const {
    return JsonResponse::IsValid() && 
           !encrypted_compression_.empty() && 
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
    if (encrypted_compression_.empty()) missing_fields.push_back("data_batch_encrypted.value_format.compression");
    if (encrypted_value_.empty()) missing_fields.push_back("data_batch_encrypted.value");
    
    return BuildValidationError(missing_fields);
}

crow::json::wvalue EncryptJsonResponse::ToJsonObject() const {
    crow::json::wvalue json;
    
    // Build data_batch_encrypted
    crow::json::wvalue data_batch_encrypted;
    crow::json::wvalue encrypted_value_format;
    encrypted_value_format["compression"] = encrypted_compression_;
    data_batch_encrypted["value_format"] = std::move(encrypted_value_format);
    data_batch_encrypted["value"] = encrypted_value_;
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
    
    return json;
}

bool DecryptJsonResponse::IsValid() const {
    return JsonResponse::IsValid() && 
           !datatype_.empty() && 
           !compression_.empty() && 
           !format_.empty() && 
           !encoding_.empty() && 
           !decrypted_value_.empty();
}

std::string DecryptJsonResponse::GetValidationError() const {
    std::vector<std::string> missing_fields;
    
    // Check base class fields
    if (user_id_.empty()) missing_fields.push_back("access.user_id");
    if (role_.empty()) missing_fields.push_back("access.role");
    if (access_control_.empty()) missing_fields.push_back("access.access_control");
    if (reference_id_.empty()) missing_fields.push_back("debug.reference_id");
    
    // Check decrypt-specific fields
    if (datatype_.empty()) missing_fields.push_back("data_batch.datatype");
    if (compression_.empty()) missing_fields.push_back("data_batch.value_format.compression");
    if (format_.empty()) missing_fields.push_back("data_batch.value_format.format");
    if (encoding_.empty()) missing_fields.push_back("data_batch.value_format.encoding");
    if (decrypted_value_.empty()) missing_fields.push_back("data_batch.value");
    
    return BuildValidationError(missing_fields);
}

crow::json::wvalue DecryptJsonResponse::ToJsonObject() const {
    crow::json::wvalue json;
    
    // Build data_batch
    crow::json::wvalue data_batch;
    data_batch["datatype"] = datatype_;
    data_batch["value"] = decrypted_value_;
    
    crow::json::wvalue value_format;
    value_format["compression"] = compression_;
    value_format["format"] = format_;
    value_format["encoding"] = encoding_;
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
    
    return json;
}
