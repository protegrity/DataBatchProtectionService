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

// Hardcoded JWT secret key for signing tokens
// TODO: Make this configurable (e.g., from environment variable or config file)
static const std::string JWT_SECRET_KEY = "default-secret-key-change-in-production";

// JWT expiration time: 4 hours in seconds
static const int JWT_EXPIRATION_SECONDS = 4 * 60 * 60;  // 14400 seconds

// ClientCredentialStore implementation

// Initialize credential store from a given map.
void ClientCredentialStore::init(const std::map<std::string, std::string>& credentials) {
    credentials_.clear();
    credentials_ = credentials;
}

// Initialize credential store from a JSON file
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
std::optional<std::string> ClientCredentialStore::GenerateJWT(const std::string& client_id, const std::string& api_key) const {
    // Validate that client_id is not empty
    if (client_id.empty()) {
        std::cerr << "Error generating JWT: client_id cannot be empty" << std::endl;
        return std::nullopt;
    }
    
    // Validate credentials before generating JWT
    if (!ValidateCredential(client_id, api_key)) {
        std::cerr << "Error generating JWT: Invalid credentials for client_id: " << client_id << std::endl;
        return std::nullopt;
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
            .sign(jwt::algorithm::hs256{JWT_SECRET_KEY});
        
        return token;
    } catch (const std::exception& e) {
        std::cerr << "Error generating JWT: " << e.what() << std::endl;
        return std::nullopt;
    }
}

// ParseAuthRequest implementation
AuthRequest ParseAuthRequest(const std::string& request_body) {
    AuthRequest auth_req;
    
    try {
        // Parse JSON request body using nlohmann::json
        nlohmann::json json_body = nlohmann::json::parse(request_body);
        
        // Validate that it's an object
        if (!json_body.is_object()) {
            auth_req.error_message = "Invalid JSON in request body";
            return auth_req;
        }
        
        // Extract client_id from request
        if (json_body.contains("client_id") && json_body["client_id"].is_string()) {
            auth_req.client_id = json_body["client_id"].get<std::string>();
        } else {
            auth_req.error_message = "Missing required field: client_id";
            return auth_req;
        }
        
        // Extract api_key from request
        if (json_body.contains("api_key") && json_body["api_key"].is_string()) {
            auth_req.api_key = json_body["api_key"].get<std::string>();
        } else {
            auth_req.error_message = "Missing required field: api_key";
            return auth_req;
        }
        
        return auth_req;
    } catch (const nlohmann::json::exception& e) {
        auth_req.error_message = "Invalid JSON in request body: " + std::string(e.what());
        return auth_req;
    } catch (const std::exception& e) {
        auth_req.error_message = "Error parsing request: " + std::string(e.what());
        return auth_req;
    }
}

