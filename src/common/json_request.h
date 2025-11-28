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

#pragma once

#include <vector>
#include <string>
#include <optional>
#include <map>
#include <cstdint>
#include "enums.h"
#include "enum_utils.h"

using namespace dbps::external;

/**
 * Base class for parsing and validating JSON request fields.
 * Contains common fields and logic shared between encrypt and decrypt requests.
 */
class JsonRequest {

public:
    // Common required fields
    // - Some fields are declared as optional to determine if these are unassigned for validation checking.
    //   However, all fields except datatype_length_ are required.
    std::string column_name_;
    std::optional<Type::type> datatype_;
    std::optional<int> datatype_length_;
    std::optional<CompressionCodec::type> compression_;
    std::optional<Format::type> format_;
    std::map<std::string, std::string> encoding_attributes_;
    std::optional<CompressionCodec::type> encrypted_compression_;
    std::string key_id_;
    std::string user_id_;
    std::string application_context_;
    std::string reference_id_;
    
    /**
     * Default constructor.
     */
    JsonRequest() = default;
    
    /**
     * Virtual destructor for proper inheritance.
     */
    virtual ~JsonRequest() = default;
    
    /**
     * Parses the JSON body and populates common fields.
     * Derived classes should call this first, then parse their specific fields.
     * @param request_body The raw request body string
     */
     void ParseCommon(const std::string& request_body);
    
    /**
     * Pure virtual method for parsing specific fields.
     * @param request_body The raw request body string
     */
    virtual void Parse(const std::string& request_body) = 0;
    
    /**
     * Validates that all common required fields are present.
     * Derived classes should override this and add their specific field validation.
     * @return true if all common required fields are set, false otherwise
     */
    virtual bool IsValid() const;
    
    /**
     * Gets a detailed error message listing all missing required fields.
     * @return String describing which fields are missing
     */
    virtual std::string GetValidationError() const;

    /**
     * Converts the parsed request object to a JSON string.
     * @return String representation of the JSON
     */
    std::string ToJson() const;

protected:
    // String parsed from datatype_length_ for validation checks
    std::string datatype_length_str_;

     /**
     * Generates a JSON string from the member variables representing the request.
     * @return String representation of the JSON
     */
    virtual std::string ToJsonString() const = 0;
};

/**
 * Class for parsing and validating encryption request fields.
 * Inherits from JsonRequest and adds encrypt-specific fields.
 */
class EncryptJsonRequest : public JsonRequest {
public:
    // Encrypt-specific required fields
    std::vector<uint8_t> value_;
    
    /**
     * Default constructor.
     */
    EncryptJsonRequest() = default;
    
    /**
     * Parses the JSON body and populates all fields.
     * @param request_body The raw request body string
     */
    void Parse(const std::string& request_body) override;
    
    /**
     * Validates that JSON is valid and all required fields are present.
     * @return true if JSON is valid and all required fields are set, false otherwise
     */
    bool IsValid() const override;
    
    /**
     * Gets a detailed error message listing all missing required fields.
     * @return String describing which fields are missing
     */
    std::string GetValidationError() const override;

protected:
    /**
     * Generates a JSON string from the member variables representing the request.
     * @return String representation of the JSON
     */
    std::string ToJsonString() const override;
};

/**
 * Class for parsing and validating decryption request fields.
 * Inherits from JsonRequest and adds decrypt-specific fields.
 */
class DecryptJsonRequest : public JsonRequest {
public:
    // Decrypt-specific required fields
    std::vector<uint8_t> encrypted_value_;
    std::map<std::string, std::string> encryption_metadata_;
    
    /**
     * Default constructor.
     */
    DecryptJsonRequest() = default;
    
    /**
     * Parses the JSON body and populates all fields.
     * @param request_body The raw request body string
     */
    void Parse(const std::string& request_body) override;
    
    /**
     * Validates that JSON is valid and all required fields are present.
     * @return true if JSON is valid and all required fields are set, false otherwise
     */
    bool IsValid() const override;
    
    /**
     * Gets a detailed error message listing all missing required fields.
     * @return String describing which fields are missing
     */
    std::string GetValidationError() const override;

protected:
    /**
     * Generates a JSON string from the member variables representing the request.
     * @return String representation of the JSON
     */
    std::string ToJsonString() const override;
};

/**
 * Base class for building and validating JSON response fields.
 * Contains common fields and logic shared between encrypt and decrypt responses.
 */
class JsonResponse {

public:
    // Common required fields
    std::string user_id_;
    std::string role_;
    std::string access_control_;
    std::string reference_id_;
    
    /**
     * Default constructor.
     */
    JsonResponse() = default;
    
    /**
     * Virtual destructor for proper inheritance.
     */
    virtual ~JsonResponse() = default;
    
    /**
     * Parses the JSON body and populates all common fields.
     * @param response_body The raw response body string
     */
    virtual void Parse(const std::string& response_body);
    
    /**
     * Validates that all common required fields are present.
     * Derived classes should override this and add their specific field validation.
     * @return true if all common required fields are set, false otherwise
     */
    virtual bool IsValid() const;
    
    /**
     * Gets a detailed error message listing all missing required fields.
     * @return String describing which fields are missing
     */
    virtual std::string GetValidationError() const;

    /**
     * Converts the response object to a JSON string.
     * @return String representation of the JSON
     */
    std::string ToJson() const;

protected:
    /**
     * Generates a JSON string from the member variables representing the response.
     * @return String representation of the JSON
     */
    virtual std::string ToJsonString() const = 0;
};

/**
 * Class for building and validating encryption response fields.
 * Inherits from JsonResponse and adds encrypt-specific fields.
 */
class EncryptJsonResponse : public JsonResponse {
public:
    // Encrypt-specific required fields
    std::optional<CompressionCodec::type> encrypted_compression_;
    std::vector<uint8_t> encrypted_value_;
    std::map<std::string, std::string> encryption_metadata_;
    
    /**
     * Default constructor.
     */
    EncryptJsonResponse() = default;
    
    /**
     * Parses the JSON body and populates all fields.
     * @param response_body The raw response body string
     */
    void Parse(const std::string& response_body) override;
    
    /**
     * Validates that all required fields are present.
     * @return true if all required fields are set, false otherwise
     */
    bool IsValid() const override;
    
    /**
     * Gets a detailed error message listing all missing required fields.
     * @return String describing which fields are missing
     */
    std::string GetValidationError() const override;

protected:
    /**
     * Generates a JSON string from the member variables representing the response.
     * @return String representation of the JSON
     */
    std::string ToJsonString() const override;
};

/**
 * Class for building and validating decryption response fields.
 * Inherits from JsonResponse and adds decrypt-specific fields.
 */
class DecryptJsonResponse : public JsonResponse {
public:
    // Decrypt-specific required fields
    std::optional<Type::type> datatype_;
    std::optional<int> datatype_length_;
    std::optional<CompressionCodec::type> compression_;
    std::optional<Format::type> format_;
    std::vector<uint8_t> decrypted_value_;
    
    /**
     * Default constructor.
     */
    DecryptJsonResponse() = default;
    
    /**
     * Parses the JSON body and populates all fields.
     * @param response_body The raw response body string
     */
    void Parse(const std::string& response_body) override;
    
    /**
     * Validates that all required fields are present.
     * @return true if all required fields are set, false otherwise
     */
    bool IsValid() const override;
    
    /**
     * Gets a detailed error message listing all missing required fields.
     * @return String describing which fields are missing
     */
    std::string GetValidationError() const override;

protected:
    // String parsed from datatype_length_ for validation checks
    std::string datatype_length_str_;

    /**
     * Generates a JSON string from the member variables representing the response.
     * @return String representation of the JSON
     */
    std::string ToJsonString() const override;
};
