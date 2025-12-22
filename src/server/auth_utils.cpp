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

#include "auth_utils.h"
#include <jwt-cpp/jwt.h>
#include <chrono>
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

// ClientCredentialStore implementation

// Constructor
ClientCredentialStore::ClientCredentialStore(const std::string& jwt_secret_key)
    : jwt_secret_key_(jwt_secret_key) {
}

// Initialize credential store from a given map.
// Expected map format:
// {
//   {"one_client_id", "one_api_key"},
//   {"another_client_id", "another_api_key"}
// }
void ClientCredentialStore::init(const std::map<std::string, std::string>& credentials) {
    credentials_.clear();
    credentials_ = credentials;
    enable_credential_check_ = true;  // Default: enable credential checking
}

// Set the enable_credential_check flag.
void ClientCredentialStore::init(bool enable_credential_check) {
    enable_credential_check_ = enable_credential_check;
}

// Initialize credential store from a JSON file
// Expected JSON file format:
// {
//   "one_client_id": "one_api_key",
//   "another_client_id": "another_api_key"
// }
bool ClientCredentialStore::init(const std::string& file_path) {
    try {
        // Open and read the JSON file
        std::ifstream file(file_path);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open credentials file: " << file_path << std::endl;
            return false;
        }
        
        // Parse JSON
        nlohmann::json json_data;
        file >> json_data;
        file.close();
        
        // Validate that it's an object
        if (!json_data.is_object()) {
            std::cerr << "Error: Credentials file must contain a JSON object" << std::endl;
            return false;
        }
        
        // Clear existing credentials
        credentials_.clear();
        enable_credential_check_ = true;  // Default: enable credential checking
        
        // Load each client_id:api_key pair
        for (auto& [client_id, api_key_value] : json_data.items()) {
            if (api_key_value.is_string()) {
                AddCredential(client_id, api_key_value.get<std::string>());
            } else {
                std::cerr << "Warning: Skipping invalid api_key for client_id: " << client_id << std::endl;
            }
        }
        
        return true;
    } catch (const nlohmann::json::exception& e) {
        std::cerr << "Error parsing JSON credentials file: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error loading credentials file: " << e.what() << std::endl;
        return false;
    }
}

// Get the enable_credential_check flag.
bool ClientCredentialStore::GetEnableCredentialCheck() const {
    return enable_credential_check_;
}

void ClientCredentialStore::AddCredential(const std::string& client_id, const std::string& api_key) {
    credentials_[client_id] = api_key;
}

bool ClientCredentialStore::ValidateCredential(const std::string& client_id, const std::string& api_key) const {
    auto it = credentials_.find(client_id);
    if (it == credentials_.end()) {
        return false;
    }
    return it->second == api_key;
}

bool ClientCredentialStore::HasClientId(const std::string& client_id) const {
    return credentials_.find(client_id) != credentials_.end();
}

// GenerateJWT implementation
std::optional<ClientCredentialStore::TokenWithExpiration> ClientCredentialStore::GenerateJWT(
    const std::string& client_id,
    const std::string& api_key) const {
    if (enable_credential_check_) {
        // Validate that client_id and api_key are not empty
        if (client_id.empty() || api_key.empty()) {
            std::cout << "Error generating JWT: client_id or api_key cannot be empty" << std::endl;
            return std::nullopt;
        }

        // Validate credentials before generating JWT
        if (!ValidateCredential(client_id, api_key)) {
            std::cout << "Error generating JWT: Invalid credentials for client_id=[" << client_id << "]" << std::endl;
            return std::nullopt;
        }
    } else {
        // Skip credential validation (and any client_id emptiness checks) if flag is not set.
        std::cout << "Warning: Credential checking is skipped. Generating JWT without validation for client_id=[" << client_id << "]" << std::endl;
    }
    
    try {
        // Get current time
        auto now = std::chrono::system_clock::now();
        auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        // Calculate expiration time (4 hours from now)
        auto exp_seconds = now_seconds + JWT_EXPIRATION_SECONDS;
        
        // Create JWT token with client_id, iat, and exp claims
        auto token = jwt::create()
            .set_type("JWT")
            .set_payload_claim("client_id", jwt::claim(client_id))
            .set_issued_at(std::chrono::system_clock::from_time_t(now_seconds))
            .set_expires_at(std::chrono::system_clock::from_time_t(exp_seconds))
            .sign(jwt::algorithm::hs256{jwt_secret_key_});
        
        return TokenWithExpiration{token, static_cast<std::int64_t>(exp_seconds)};
    } catch (const std::exception& e) {
        std::cerr << "Error generating JWT: " << e.what() << std::endl;
        return std::nullopt;
    }
}

// ProcessTokenRequest implementation
TokenResponse ClientCredentialStore::ProcessTokenRequest(const std::string& request_body) const {
    TokenResponse response;
    
    // Parse token request
    TokenRequest token_req;
    auto error_opt = token_req.ParseWithError(request_body);
    if (error_opt.has_value()) {
        response.SetErrorStatusCodeAndClearToken(400);
        response.error_message_ = error_opt.value();
        return response;
    }
    
    // Get client_id and api_key from the parsed token request.
    const auto client_id_it = token_req.credential_values_.find("client_id");
    const auto api_key_it = token_req.credential_values_.find("api_key");
    const std::string client_id = (client_id_it != token_req.credential_values_.end()) ? client_id_it->second : "";
    const std::string api_key = (api_key_it != token_req.credential_values_.end()) ? api_key_it->second : "";

    // Get printables for client_id and api_key
    const std::string client_id_prn =
        std::string("client_id=[") + (client_id.empty() ? std::string("<empty>") : client_id) + "]";
    const std::string api_key_prn =
        std::string("api_key=[") + (api_key.empty() ? std::string("<empty>") : std::string("<redacted>")) + "]";

    // Print a warning if client_id or api_key is missing, but proceed with the request.
    if (client_id.empty() || api_key.empty()) {
        std::cout << "ProcessTokenRequest -- Warning: Missing client_id or api_key. Proceeding with the request. "
            << client_id_prn << ", " << api_key_prn << std::endl;
    } else {
        std::cout << "ProcessTokenRequest -- " << client_id_prn << ", " << api_key_prn << std::endl;
    }

    // Generate JWT token (validates credentials internally)
    auto token = GenerateJWT(client_id, api_key);
    
    if (!token.has_value()) {
        response.SetErrorStatusCodeAndClearToken(401);
        response.error_message_ = "Invalid credentials -- " + client_id_prn + ", " + api_key_prn;
        return response;
    }
    
    response.token_ = token->token;
    response.token_type_ = JWT_TOKEN_TYPE;
    response.expires_at_ = token->expires_at;
    response.error_status_code_ = 200;
    std::cout << "ProcessTokenRequest -- Token generated successfully for " << client_id_prn << std::endl;

    return response;
}

// VerifyJWT implementation
std::optional<std::string> VerifyJWT(const std::string& token, const std::string& jwt_secret_key) {
    try {
        // Decode and verify the JWT token
        auto decoded = jwt::decode(token);
        
        // Verify the signature using the same secret key
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{jwt_secret_key});
        
        verifier.verify(decoded);
        
        // Extract client_id from the token payload
        if (decoded.has_payload_claim("client_id")) {
            auto client_id_claim = decoded.get_payload_claim("client_id");
            return client_id_claim.as_string();
        } else {
            std::cerr << "Error verifying JWT: Missing client_id claim in token" << std::endl;
            return std::nullopt;
        }
    } catch (const jwt::error::token_verification_exception& e) {
        std::cerr << "Error verifying JWT: Token verification failed - " << e.what() << std::endl;
        return std::nullopt;
    } catch (const std::exception& e) {
        std::cerr << "Error verifying JWT: " << e.what() << std::endl;
        return std::nullopt;
    }
}

// VerifyTokenForEndpoint implementation
std::optional<std::string> ClientCredentialStore::VerifyTokenForEndpoint(const std::string& authorization_header) const {
    // Skip verification if credential checking is disabled
    if (!enable_credential_check_) {
        return std::nullopt;
    }
    
    // Extract token from Authorization header
    std::optional<std::string> token = std::nullopt;
    const std::string expected_prefix = JWT_TOKEN_TYPE + " ";
    if (authorization_header.rfind(expected_prefix, 0) == 0) {  // starts_with(expected_prefix)
        token = authorization_header.substr(expected_prefix.size());
    }
    
    // Verify JWT token
    if (!token.has_value()) {
        return "Unauthorized: JWT token is missing";
    }
    
    auto client_id = VerifyJWT(token.value(), jwt_secret_key_);
    if (!client_id.has_value()) {
        return "Unauthorized: Invalid JWT token";
    }
    
    std::cout << "JWT verified for client_id: " << client_id.value() << std::endl;
    return std::nullopt;
}
