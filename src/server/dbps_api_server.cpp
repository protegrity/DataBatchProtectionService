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

#include <crow/app.h>
#include <string>
#include <optional>
#include "json_request.h"
#include "encryption_sequencer.h"
#include "auth_utils.h"

// Helper function to create error response
crow::response CreateErrorResponse(const std::string& error_msg, int status_code = 400) {
    std::cout << "CreateErrorResponse: Status=" << status_code << ", Message=\"" << error_msg << "\"" << std::endl;
    crow::json::wvalue error_response;
    error_response["error"] = error_msg;
    return crow::response(status_code, error_response);
}

int main() {
    crow::SimpleApp app;

    // Initialize credential store
    // TODO: Make credentials file path configurable.
    ClientCredentialStore credential_store;
    const std::string credentials_file_path = "credentials.json";  // Default path
    if (!credential_store.init(credentials_file_path)) {
        std::cout << "Warning: Failed to load credentials file: " << credentials_file_path << std::endl;
        std::cout << "Server will continue to run, but credentials will not be validated." << std::endl;
    } else {
        std::cout << "Credentials loaded successfully from: " << credentials_file_path << std::endl;
    }

    CROW_ROUTE(app, "/healthz")([] {
        return "OK";
    });

    CROW_ROUTE(app, "/statusz")([]{
        crow::json::wvalue response;
        response["status"] = "chill";
        response["system_settings"] = "set to thrill!";
        return crow::response(200, response);
    });

    // Authentication endpoint - POST /auth
    CROW_ROUTE(app, "/auth").methods("POST"_method)([&credential_store](const crow::request& req) {
        // Parse authentication request
        AuthRequest auth_req = ParseAuthRequest(req.body);
        
        // Check if parsing resulted in an error
        if (auth_req.error_message.has_value()) {
            return CreateErrorResponse(auth_req.error_message.value(), 400);
        }
        
        // Log the request for debugging
        std::cout << "=== /auth Request ===" << std::endl;
        std::cout << "client_id: " << auth_req.client_id << std::endl;
        std::cout << "====================" << std::endl;
        
        // Generate JWT token (validates credentials internally)
        auto token = credential_store.GenerateJWT(auth_req.client_id, auth_req.api_key);
        
        if (!token.has_value()) {
            return CreateErrorResponse("Invalid credentials", 401);
        }
        
        // Create success response
        crow::json::wvalue response;
        response["token"] = token.value();
        response["token_type"] = "Bearer";
        response["expires_in"] = 14400;  // 4 hours in seconds
        
        std::cout << "=== /auth Response (Success) ===" << std::endl;
        std::cout << "Token generated for client_id: " << auth_req.client_id << std::endl;
        std::cout << "=================================" << std::endl;
        
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

        // Log the validated request JSON for debugging
        std::cout << "=== /encrypt Request (Validated) ===" << std::endl;
        std::cout << request.ToJson() << std::endl;
        std::cout << "=====================================" << std::endl;

        // Create response using our JsonResponse class
        EncryptJsonResponse response;
        
        // Use DataBatchEncryptionSequencer for actual encryption
        // It is safe to use value() because the request is validated above.
        DataBatchEncryptionSequencer sequencer(
            request.column_name_,
            request.datatype_.value(),
            request.datatype_length_,
            request.compression_.value(),
            request.format_.value(),
            request.encoding_attributes_,
            request.encrypted_compression_.value(),
            request.key_id_,
            request.user_id_,
            request.application_context_
        );
        
        try {
            bool encrypt_result = sequencer.ConvertAndEncrypt(request.value_);
            if (!encrypt_result) {
                return CreateErrorResponse("Encryption failed: " + sequencer.error_stage_ + " - " + sequencer.error_message_);
            }
        } catch (const InvalidInputException& e) {
            return CreateErrorResponse("Invalid input for encryption: " + std::string(e.what()));
        }
        
        // Set encrypted value
        response.encrypted_value_ = sequencer.encrypted_result_;
        
        // Set common fields of response
        // TODO: Add role and access control logic based on context-aware access control logic during encryption.
        response.user_id_ = request.user_id_;
        response.role_ = "EmailReader";  // This would be determined by access control logic
        response.access_control_ = "granted";
        response.reference_id_ = request.reference_id_;
        response.encrypted_compression_ = request.encrypted_compression_;
        
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

        // Log the validated request JSON for debugging
        std::cout << "=== /decrypt Request (Validated) ===" << std::endl;
        std::cout << request.ToJson() << std::endl;
        std::cout << "=====================================" << std::endl;

        // Create response using our JsonResponse class
        DecryptJsonResponse response;
        
        // Set common fields of response
        // TODO: Add role and access control logic based on context-aware access control logic during decryption.
        response.user_id_ = request.user_id_;
        response.role_ = "EmailReader";  // This would be determined by access control logic
        response.access_control_ = "granted";
        response.reference_id_ = request.reference_id_;
        
        // Set decrypt-specific fields
        response.datatype_ = request.datatype_;
        response.datatype_length_ = request.datatype_length_;
        response.compression_ = request.compression_;
        response.format_ = request.format_;
        
        // Use DataBatchEncryptionSequencer for actual decryption
        // It is safe to use value() because the request is validated above.
        DataBatchEncryptionSequencer sequencer(
            request.column_name_,
            request.datatype_.value(),
            request.datatype_length_,
            request.compression_.value(),
            request.format_.value(),
            request.encoding_attributes_,
            request.encrypted_compression_.value(),
            request.key_id_,
            request.user_id_,
            request.application_context_
        );
        
        try {
            bool decrypt_result = sequencer.ConvertAndDecrypt(request.encrypted_value_);
            if (!decrypt_result) {
                return CreateErrorResponse("Decryption failed: " + sequencer.error_stage_ + " - " + sequencer.error_message_);
            }
        } catch (const std::exception& e) {
            return CreateErrorResponse("Decryption failed: " + std::string(e.what()));
        }
        
        response.decrypted_value_ = sequencer.decrypted_result_;
        
        // Generate JSON response using our class
        std::string response_json = response.ToJson();
        return crow::response(200, response_json);
    });

    app.port(18080).multithreaded().run();
}
