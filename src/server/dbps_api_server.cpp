#include <crow/app.h>
#include <string>
#include "json_request.h"



// Helper function to create error response
crow::response CreateErrorResponse(const std::string& error_msg, int status_code = 400) {
    crow::json::wvalue error_response;
    error_response["error"] = error_msg;
    return crow::response(status_code, error_response);
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
        return crow::response(200, response);
    });

    // Encryption endpoint - POST /encrypt
    CROW_ROUTE(app, "/encrypt").methods("POST"_method)([](const crow::request& req) {
        // Parse and validate request using our new class
        EncryptJsonRequest request;
        request.Parse(req.body);
        
        if (!request.IsValid()) {
            std::string error_msg = request.GetValidationError();
            if (error_msg.empty()) {
                error_msg = "Invalid JSON in request body";
            }
            return CreateErrorResponse(error_msg);
        }

        // For now, we'll simulate encryption by creating a "processed" version of the input
        // In a real implementation, this would involve actual encryption logic        
        crow::json::wvalue response;

        // Build data_batch_encrypted structure using the requested compression
        crow::json::wvalue data_batch_encrypted;
        data_batch_encrypted["value_format"]["compression"] = request.encrypted_compression_;
        // Simulate encryption by adding "ENCRYPTED_" prefix to the value
        data_batch_encrypted["value"] = "ENCRYPTED_" + request.value_;
        response["data_batch_encrypted"] = std::move(data_batch_encrypted);

        // Build access structure using the actual user_id
        crow::json::wvalue access;
        access["user_id"] = request.user_id_;
        access["role"] = "EmailReader";  // This would be determined by access control logic
        access["access_control"] = "granted";
        response["access"] = std::move(access);

        // Build debug structure with reference_id (now mandatory)
        crow::json::wvalue debug;
        debug["reference_id"] = request.reference_id_;
        response["debug"] = std::move(debug);

        return crow::response(200, response);
    });

    // Decryption endpoint - POST /decrypt
    CROW_ROUTE(app, "/decrypt").methods("POST"_method)([](const crow::request& req) {
        // Parse and validate request using our new class
        DecryptJsonRequest request;
        request.Parse(req.body);
        
        if (!request.IsValid()) {
            std::string error_msg = request.GetValidationError();
            if (error_msg.empty()) {
                error_msg = "Invalid JSON in request body";
            }
            return CreateErrorResponse(error_msg);
        }

        // For now, we'll simulate decryption by removing the "ENCRYPTED_" prefix
        // In a real implementation, this would involve actual decryption logic        
        crow::json::wvalue response;

        // Build data_batch structure using the requested format
        crow::json::wvalue data_batch;
        data_batch["datatype"] = request.datatype_;
        data_batch["value_format"]["compression"] = request.compression_;
        data_batch["value_format"]["format"] = request.format_;
        data_batch["value_format"]["encoding"] = request.encoding_;
        // Simulate decryption by removing "ENCRYPTED_" prefix if present
        std::string decrypted_value = request.encrypted_value_;
        const std::string encrypted_prefix = "ENCRYPTED_";
        if (decrypted_value.starts_with(encrypted_prefix)) {
            decrypted_value = decrypted_value.substr(encrypted_prefix.length());
        }
        data_batch["value"] = decrypted_value;
        response["data_batch"] = std::move(data_batch);

        // Build access structure using the actual user_id
        crow::json::wvalue access;
        access["user_id"] = request.user_id_;
        access["role"] = "EmailReader";  // This would be determined by access control logic
        access["access_control"] = "granted";
        response["access"] = std::move(access);

        // Build debug structure with reference_id (now mandatory)
        crow::json::wvalue debug;
        debug["reference_id"] = request.reference_id_;
        // Add pretty_printed_value for decryption (simulate human-readable output)
        debug["pretty_printed_value"] = "user1@example.com\nuser2@example.com";
        response["debug"] = std::move(debug);

        return crow::response(200, response);
    });

    app.port(18080).multithreaded().run();
}
