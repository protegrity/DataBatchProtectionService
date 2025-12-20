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

// Note for Protegrity integration:
// - This is a simplified Authentication module used to complete the client integration.
// - It is fully functional, but for production deployment a fully fledged Certificate Authority or Identity Provider can be used instead.
//
// - Note that no Arrow codebase changes would be needed to replace this with a fully fledged Certificate Authority (CA) or Identity Provider
//   as the connection configuration specified on the application level is passed as-is to the DBPS agents for authentication.

#pragma once

#include <map>
#include <string>
#include <optional>
#include <cstdint>
#include "json_request.h"

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

// JWT expiration time: 4 hours in seconds
inline constexpr int JWT_EXPIRATION_SECONDS = 4 * 60 * 60;  // 14400 seconds
inline const std::string JWT_TOKEN_TYPE = "Bearer";

/**
 * ClientCredentialStore manages client_id to api_key mappings for authentication.
 * 
 * - Loads client credentials from a Json file and stores them in-memory.
 * - Generates a JWT token for a given client_id.
 *
 * Integration point for Protegrity:
 * - This request can be updated with a production configuration for authentication or credentials checking.
 * - The specific fields are transparent to the library users. The API call payload of the token request is passed as-is to the module,
 *   so library users don't parse the request payload.
 */
class DBPS_EXPORT ClientCredentialStore {
public:
    /**
     * Constructor for ClientCredentialStore.
     * @param jwt_secret_key The secret key used for signing and verifying JWT tokens
     */
    explicit ClientCredentialStore(const std::string& jwt_secret_key);
    ~ClientCredentialStore() = default;
    
    /**
     * Initializes the credential store by loading credentials from a JSON file.
     * The file should contain a JSON object with client_id as keys and api_key as values.
     * Example format: {"client1": "api_key_1", "client2": "api_key_2"}
     */
    bool init(const std::string& file_path);
    
    /**
     * Initializes the credential store with a pre-built map of client_id to api_key.
     * @param credentials Map of client_id to api_key pairs
     */
    void init(const std::map<std::string, std::string>& credentials);
    
    /**
     * Sets the enable_credential_check flag.
     * @param enable_credential_check If true, credential validation will be enabled during GenerateJWT
     */
    void init(bool enable_credential_check);
    
    /**
     * Gets the enable_credential_check flag.
     * @return true if credential validation is enabled, false otherwise
     */
    bool GetEnableCredentialCheck() const;
    
    /**
     * Processes a token request from JSON body and generates a JWT token.
     * This method encapsulates all token request processing logic, hiding the details
     * of TokenRequest structure from the caller.
     * 
     * @param request_body The raw JSON request body string
     * @return TokenResponse with token if successful, or GetValidationError() and error_status_code if failed
     */
     TokenResponse ProcessTokenRequest(const std::string& request_body) const;

     /**
     * Verifies JWT token from Authorization header for protected endpoints.
     * @param authorization_header The Authorization header value (e.g., "<token_type> <token>")
     * @return Error message if verification fails, or std::nullopt if verification succeeds
     */
    std::optional<std::string> VerifyTokenForEndpoint(const std::string& authorization_header) const;
    
private:
    // Private struct to hold the token and expiration time during JWT generation requests.
    // It is intentionally separated from the client-side authentication logic to avoid server<>client coupling.
    struct TokenWithExpiration {
        std::string token;
        std::int64_t expires_at;
    };

    // Adds a client credential to the in-memory storage.
    void AddCredential(const std::string& client_id, const std::string& api_key);
    
    // Check if a client credential is valid before generating a JWT token.
    bool ValidateCredential(const std::string& client_id, const std::string& api_key) const;
    
    // Check if a a credential for a client_id exists
    bool HasClientId(const std::string& client_id) const;

    /**
     * Generates a JWT token for the given client_id if the credentials are valid.
     * 
     * The JWT includes:
     * - client_id: The client identifier
     * - iat: Issued at timestamp
     * - exp: Expiration timestamp (4 hours from issue time)
     * 
     * Uses HS256 algorithm with a hardcoded secret key.
     * 
     * @param client_id The client identifier to validate and include in the JWT
     * @param api_key The API key to validate against the stored credential
     * @return TokenWithExpiration if credentials are valid, or std::nullopt on error or invalid credentials
     */
     std::optional<TokenWithExpiration> GenerateJWT(
         const std::string& client_id,
         const std::string& api_key) const;
    
    // In-memory storage: client_id -> api_key
    std::map<std::string, std::string> credentials_;
    
    // Flag to indicate if credential checking is enabled during GenerateJWT
    bool enable_credential_check_ = true;
    
    // JWT secret key for signing and verifying tokens
    std::string jwt_secret_key_;
};
