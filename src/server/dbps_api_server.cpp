#include <crow/app.h>
#include <vector>
#include <string>
#include <iostream>

// Helper function to create error response
crow::response CreateErrorResponse(const std::string& error_msg, int status_code = 400) {
    crow::json::wvalue error_response;
    error_response["error"] = error_msg;
    return crow::response(status_code, error_response);
}

/**
 * Safely extracts a string value from a nested JSON path.
 *
 * Traverses a JSON object following a specified path and returns
 * the string value at the end of the path. If any part of the path doesn't exist
 * or if an exception occurs during traversal, it returns std::nullopt.
 *
 * Converts any JSON type to string using std::string().
 * For objects and arrays, this will return the JSON string representation.
 */
std::optional<std::string> SafeGetFromJsonPath(const crow::json::rvalue& json, const std::vector<std::string>& path) {
    try {
        const crow::json::rvalue* current = &json;
        for (const auto& field : path) {
            if (!current->has(field)) {
                return std::nullopt;
            }
            current = &((*current)[field]);
        }
        return std::string(*current);
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Exception in SafeGetFromJsonPath: " << e.what();
        return std::nullopt;
    }
}

int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/healthz")([] {
        return "OK";
    });

    CROW_ROUTE(app, "/statusz")([]{
        crow::json::wvalue response;
        response["status"] = "chill";
        response["system_settings"] = "set to thrill!";
        return response;
    });

    // Encryption endpoint - POST /encrypt
    CROW_ROUTE(app, "/encrypt").methods("POST"_method)([](const crow::request& req) {
        // Parse the JSON request body
        auto json_body = crow::json::load(req.body);
        if (!json_body) {
            return CreateErrorResponse("Invalid JSON in request body");
        }
        
        // Extract required fields from the request body payload
        auto column_name = SafeGetFromJsonPath(json_body, {"column_reference", "name"});
        auto datatype = SafeGetFromJsonPath(json_body, {"data_batch", "datatype"});
        auto compression = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "compression"});
        auto format = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "format"});
        auto encoding = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "encoding"});
        auto value = SafeGetFromJsonPath(json_body, {"data_batch", "value"});
        auto encrypted_compression = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value_format", "compression"});
        auto key_id = SafeGetFromJsonPath(json_body, {"encryption", "key_id"});
        auto user_id = SafeGetFromJsonPath(json_body, {"access", "user_id"});
        
        // Check for missing required fields and return error response
        if (!column_name)return CreateErrorResponse("Missing required field: column_reference.name");
        if (!datatype) return CreateErrorResponse("Missing required field: data_batch.datatype");
        if (!compression) return CreateErrorResponse("Missing required field: data_batch.value_format.compression");
        if (!format) return CreateErrorResponse("Missing required field: data_batch.value_format.format");
        if (!encoding) return CreateErrorResponse("Missing required field: data_batch.value_format.encoding");
        if (!value) return CreateErrorResponse("Missing required field: data_batch.value");
        if (!encrypted_compression) return CreateErrorResponse("Missing required field: data_batch_encrypted.value_format.compression");
        if (!key_id) return CreateErrorResponse("Missing required field: encryption.key_id");
        if (!user_id) return CreateErrorResponse("Missing required field: access.user_id");

        // For now, we'll simulate encryption by creating a "processed" version of the input
        // In a real implementation, this would involve actual encryption logic        
        crow::json::wvalue response;

        // Build data_batch_encrypted structure using the requested compression
        crow::json::wvalue data_batch_encrypted;
        data_batch_encrypted["value_format"]["compression"] = *encrypted_compression;
        // Simulate encryption by adding "ENCRYPTED_" prefix to the value
        data_batch_encrypted["value"] = "ENCRYPTED_" + *value;
        response["data_batch_encrypted"] = std::move(data_batch_encrypted);

        // Build access structure using the actual user_id
        crow::json::wvalue access;
        access["user_id"] = *user_id;
        access["role"] = "EmailReader";  // This would be determined by access control logic
        access["access_control"] = "granted";
        response["access"] = std::move(access);

        // Build debug structure only if reference_id was provided in request
        auto request_reference_id = SafeGetFromJsonPath(json_body, {"debug", "reference_id"});
        if (request_reference_id) {
            crow::json::wvalue debug;
            debug["reference_id"] = *request_reference_id;
            response["debug"] = std::move(debug);
        }

        return crow::response(200, response);
    });

    // Decryption endpoint - POST /decrypt
    CROW_ROUTE(app, "/decrypt").methods("POST"_method)([](const crow::request& req) {
        // Parse the JSON request body
        auto json_body = crow::json::load(req.body);
        if (!json_body) {
            return CreateErrorResponse("Invalid JSON in request body");
        }
        
        // Extract required fields from the request body payload
        auto column_name = SafeGetFromJsonPath(json_body, {"column_reference", "name"});
        auto encrypted_compression = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value_format", "compression"});
        auto encrypted_value = SafeGetFromJsonPath(json_body, {"data_batch_encrypted", "value"});
        auto datatype = SafeGetFromJsonPath(json_body, {"data_batch", "datatype"});
        auto compression = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "compression"});
        auto format = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "format"});
        auto encoding = SafeGetFromJsonPath(json_body, {"data_batch", "value_format", "encoding"});
        auto key_id = SafeGetFromJsonPath(json_body, {"encryption", "key_id"});
        auto user_id = SafeGetFromJsonPath(json_body, {"access", "user_id"});
        
        // Check for missing required fields and return error response
        if (!column_name) return CreateErrorResponse("Missing required field: column_reference.name");
        if (!encrypted_compression) return CreateErrorResponse("Missing required field: data_batch_encrypted.value_format.compression");
        if (!encrypted_value) return CreateErrorResponse("Missing required field: data_batch_encrypted.value");
        if (!datatype) return CreateErrorResponse("Missing required field: data_batch.datatype");
        if (!compression) return CreateErrorResponse("Missing required field: data_batch.value_format.compression");
        if (!format) return CreateErrorResponse("Missing required field: data_batch.value_format.format");
        if (!encoding) return CreateErrorResponse("Missing required field: data_batch.value_format.encoding");
        if (!key_id) return CreateErrorResponse("Missing required field: encryption.key_id");
        if (!user_id) return CreateErrorResponse("Missing required field: access.user_id");

        // For now, we'll simulate decryption by removing the "ENCRYPTED_" prefix
        // In a real implementation, this would involve actual decryption logic        
        crow::json::wvalue response;

        // Build data_batch structure using the requested format
        crow::json::wvalue data_batch;
        data_batch["datatype"] = *datatype;
        data_batch["value_format"]["compression"] = *compression;
        data_batch["value_format"]["format"] = *format;
        data_batch["value_format"]["encoding"] = *encoding;
        // Simulate decryption by removing "ENCRYPTED_" prefix if present
        std::string decrypted_value = *encrypted_value;
        if (decrypted_value.substr(0, 10) == "ENCRYPTED_") {
            decrypted_value = decrypted_value.substr(10);
        }
        data_batch["value"] = decrypted_value;
        response["data_batch"] = std::move(data_batch);

        // Build access structure using the actual user_id
        crow::json::wvalue access;
        access["user_id"] = *user_id;
        access["role"] = "EmailReader";  // This would be determined by access control logic
        access["access_control"] = "granted";
        response["access"] = std::move(access);

        // Build debug structure only if reference_id was provided in request
        auto request_reference_id = SafeGetFromJsonPath(json_body, {"debug", "reference_id"});
        if (request_reference_id) {
            crow::json::wvalue debug;
            debug["reference_id"] = *request_reference_id;
            // Add pretty_printed_value for decryption (simulate human-readable output)
            debug["pretty_printed_value"] = "user1@example.com\nuser2@example.com";
            response["debug"] = std::move(debug);
        }

        return crow::response(200, response);
    });

    app.port(18080).multithreaded().run();
}
