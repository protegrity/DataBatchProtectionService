#include "json_request.h"

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
    
    // Extract common optional fields
    reference_id_ = SafeGetFromJsonPath(json_body, {"debug", "reference_id"});
}

bool JsonRequest::IsValid() const {
    return !column_name_.empty() && 
           !datatype_.empty() && 
           !compression_.empty() && 
           !format_.empty() && 
           !encoding_.empty() && 
           !encrypted_compression_.empty() && 
           !key_id_.empty() && 
           !user_id_.empty();
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
    
    if (missing_fields.empty()) {
        return "";
    }
    
    std::string error_msg = "Missing required fields: ";
    for (size_t i = 0; i < missing_fields.size(); ++i) {
        if (i > 0) error_msg += ", ";
        error_msg += missing_fields[i];
    }
    return error_msg;
}

std::optional<std::string> JsonRequest::SafeGetFromJsonPath(const crow::json::rvalue& json_body, const std::vector<std::string>& path) const {
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
