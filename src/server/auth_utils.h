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
// - It is fully functional, but for production deployment a fully fledged Identity Provider can be used instead.
//
// TODO: Expand explanation below.
// - Note that no Arrow codebase changes would be needed to replace this with a fully fledged Identity Provider
//   as the connection configuration specified on the application level is passed as-is to the DBPS agents for authentication.

#pragma once

#include <map>
#include <string>
#include <optional>

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

/**
 * Structure to hold parsed token request data.
 *
 * Integration point for Protegrity:
 * - This request can be updated with the production configuration for authentication or credentials checking.
 * - The specific fields are transparent to the library users. The API call payload of the token request is passed as-is to the module,
 *   so library users don't parse the request payload.
 */
 struct DBPS_EXPORT TokenRequest {
    std::string client_id;
    std::string api_key;
    std::optional<std::string> error_message;  // Error message if parsing failed
};

/**
 * Structure to hold token generation result.
 */
struct DBPS_EXPORT TokenResponse {
    std::optional<std::string> token;
    std::optional<std::string> error_message;
    int error_status_code = 400;  // HTTP status code for error response
};

/**
 * ClientCredentialStore manages client_id to api_key mappings for authentication.
 * 
 * - Loads client credentials from a Json file and stores them in-memory.
 * - Generates a JWT token for a given client_id.
 */
class DBPS_EXPORT ClientCredentialStore {
public:
    ClientCredentialStore() = default;
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
     * Sets the skip_credential_check flag.
     * @param skip_credential_check If true, credential validation will be skipped during GenerateJWT
     */
    void init(bool skip_credential_check);
    
    /**
     * Gets the skip_credential_check flag.
     * @return true if credential validation is skipped, false otherwise
     */
    bool GetSkipCredentialCheck() const;
    
    /**
     * Processes a token request from JSON body and generates a JWT token.
     * This method encapsulates all token request processing logic, hiding the details
     * of TokenRequest structure from the caller.
     * 
     * @param request_body The raw JSON request body string
     * @return TokenResponse with token if successful, or error_message and error_status_code if failed
     */
     TokenResponse ProcessTokenRequest(const std::string& request_body) const;

     /**
     * Verifies JWT token from Authorization header for protected endpoints.
     * @param authorization_header The Authorization header value (e.g., "Bearer <token>")
     * @return Error message if verification fails, or std::nullopt if verification succeeds
     */
    std::optional<std::string> VerifyTokenForEndpoint(const std::string& authorization_header) const;
    
private:
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
     * @return The JWT token as a string if credentials are valid, or std::nullopt on error or invalid credentials
     */
     std::optional<std::string> GenerateJWT(const std::string& client_id, const std::string& api_key) const;
    
    // In-memory storage: client_id -> api_key
    std::map<std::string, std::string> credentials_;
    
    // Flag to indicate if credential checking should be skipped during GenerateJWT
    bool skip_credential_check_ = false;
};
