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

        // Create response using our JsonResponse class
        EncryptJsonResponse response;
        
        // Set common fields
        response.user_id_ = request.user_id_;
        response.role_ = "EmailReader";  // This would be determined by access control logic
        response.access_control_ = "granted";
        response.reference_id_ = request.reference_id_;
        response.encrypted_compression_ = request.encrypted_compression_;

        // For now, we'll simulate encryption by creating a "processed" version of the input
        // Simulate encryption by adding "ENCRYPTED_" prefix to the value
        response.encrypted_value_ = "ENCRYPTED_" + request.value_;
        
        // Generate JSON response using our class
        std::string response_json = response.ToJson();
        return crow::response(200, response_json);
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

        // Create response using our JsonResponse class
        DecryptJsonResponse response;
        
        // Set common fields
        response.user_id_ = request.user_id_;
        response.role_ = "EmailReader";  // This would be determined by access control logic
        response.access_control_ = "granted";
        response.reference_id_ = request.reference_id_;
        
        // Set decrypt-specific fields
        response.datatype_ = request.datatype_;
        response.compression_ = request.compression_;
        response.format_ = request.format_;
        response.encoding_ = request.encoding_;
        
        // For now, we'll simulate decryption by creating a "processed" version of the input
        // Simulate decryption by removing "ENCRYPTED_" prefix if present
        std::string decrypted_value = request.encrypted_value_;
        const std::string encrypted_prefix = "ENCRYPTED_";
        if (decrypted_value.starts_with(encrypted_prefix)) {
            decrypted_value = decrypted_value.substr(encrypted_prefix.length());
        }
        response.decrypted_value_ = decrypted_value;
        
        // Generate JSON response using our class
        std::string response_json = response.ToJson();
        return crow::response(200, response_json);
    });

    app.port(18080).multithreaded().run();
}
