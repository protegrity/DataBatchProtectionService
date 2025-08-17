#pragma once

#include <crow/app.h>
#include <vector>
#include <string>
#include <optional>

/**
* Safely extracts a string value from a nested JSON path.
*
* Traverses a JSON object following a specified path and returns
* the string value at the end of the path. If any part of the path doesn't exist
* or if an exception occurs during traversal, it returns std::nullopt.
*
* @param json_body The JSON object to traverse
* @param path Vector of strings representing the path to traverse
* @return std::optional<std::string> containing the value if found, std::nullopt otherwise
*/
std::optional<std::string> SafeGetFromJsonPath(const crow::json::rvalue& json_body, const std::vector<std::string>& path);

/**
 * Base class for parsing and validating JSON request fields.
 * Contains common fields and logic shared between encrypt and decrypt requests.
 */
class JsonRequest {

public:
    // Common required fields
    std::string column_name_;
    std::string datatype_;
    std::string compression_;
    std::string format_;
    std::string encoding_;
    std::string encrypted_compression_;
    std::string key_id_;
    std::string user_id_;
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
    /**
     * Converts the parsed request object back to JSON format.
     * @return crow::json::wvalue representing the current state of the object
     */
    virtual crow::json::wvalue ToJsonObject() const = 0;
};

/**
 * Class for parsing and validating encryption request fields.
 * Inherits from JsonRequest and adds encrypt-specific fields.
 */
class EncryptJsonRequest : public JsonRequest {
public:
    // Encrypt-specific required fields
    std::string value_;
    
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
     * Converts the parsed request object back to JSON format.
     * @return crow::json::wvalue representing the current state of the object
     */
    crow::json::wvalue ToJsonObject() const override;
};

/**
 * Class for parsing and validating decryption request fields.
 * Inherits from JsonRequest and adds decrypt-specific fields.
 */
class DecryptJsonRequest : public JsonRequest {
public:
    // Decrypt-specific required fields
    std::string encrypted_value_;
    
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
     * Converts the parsed request object back to JSON format.
     * @return crow::json::wvalue representing the current state of the object
     */
    crow::json::wvalue ToJsonObject() const override;
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
     * Converts the response object back to JSON format.
     * @return crow::json::wvalue representing the current state of the object
     */
    virtual crow::json::wvalue ToJsonObject() const = 0;
};

/**
 * Class for building and validating encryption response fields.
 * Inherits from JsonResponse and adds encrypt-specific fields.
 */
class EncryptJsonResponse : public JsonResponse {
public:
    // Encrypt-specific required fields
    std::string encrypted_compression_;
    std::string encrypted_value_;
    
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
     * Converts the response object back to JSON format.
     * @return crow::json::wvalue representing the current state of the object
     */
    crow::json::wvalue ToJsonObject() const override;
};

/**
 * Class for building and validating decryption response fields.
 * Inherits from JsonResponse and adds decrypt-specific fields.
 */
class DecryptJsonResponse : public JsonResponse {
public:
    // Decrypt-specific required fields
    std::string datatype_;
    std::string compression_;
    std::string format_;
    std::string encoding_;
    std::string decrypted_value_;
    
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
    /**
     * Converts the response object back to JSON format.
     * @return crow::json::wvalue representing the current state of the object
     */
    crow::json::wvalue ToJsonObject() const override;
};
