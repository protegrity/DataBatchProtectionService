#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>

#include "../common/enums.h"
#include "../common/enum_utils.h"
#include "../common/json_request.h"
#include "../common/tcb/span.hpp"
#include "http_client_interface.h"

using namespace dbps::external;
using namespace dbps::enum_utils;

template <typename T>
using span = tcb::span<T>;

// API response wrapper that contains comprehensive information about the client-server call
class ApiResponse {
public:
    // Empty constructor
    ApiResponse() = default;
    
    // Success check - consider success if we have a response, no client error, 2xx HTTP status code, 
    // and valid response
    bool Success() const;
    
    // Returns an error message for the condition that caused the failure.
    std::string ErrorMessage() const;
    
    // Returns a map of error fields for debugging
    std::map<std::string, std::string> ErrorFields() const;

public:
    // Setters for response data (internal use)
    void SetHttpStatusCode(int code);
    void SetApiClientError(const std::string& error);
    void SetRawResponse(const std::string& raw_response);

protected:
    // Virtual methods for subclasses to implement (internal use)
    virtual bool HasJsonResponse() const = 0;
    virtual const JsonResponse& GetJsonResponse() const = 0;
    virtual bool HasJsonRequest() const = 0;
    virtual const JsonRequest& GetJsonRequest() const = 0;
    
    // Check methods (internal use)
    bool HasHttpStatusCode() const;
    bool HasApiClientError() const;
    bool HasRawResponse() const;
    
    // Getters (internal use)
    int GetHttpStatusCode() const;
    const std::string& GetApiClientError() const;
    const std::string& GetRawResponse() const;
    
    std::optional<int> http_status_code_;
    std::optional<std::string> api_client_error_;
    std::optional<std::string> raw_response_;
};

// Encryption API response wrapper
class EncryptApiResponse : public ApiResponse {
public:
    // Returns the encrypted value as binary data (decoded from base64)
    span<const uint8_t> GetResponseCiphertext() const;
    
    const EncryptJsonResponse& GetResponseAttributes() const;

public:
    // Setters for encryption-specific response
    void SetJsonResponse(const EncryptJsonResponse& response);
    void SetJsonRequest(const EncryptJsonRequest& request);

protected:
    // Getters for encryption-specific response (override protected base methods)
    const EncryptJsonResponse& GetJsonResponse() const override;
    bool HasJsonResponse() const override;
    
    // Check and get methods for encryption-specific request (override virtual base methods)
    const JsonRequest& GetJsonRequest() const override;
    bool HasJsonRequest() const override;    
    
    std::optional<EncryptJsonResponse> encrypt_response_;
    std::optional<EncryptJsonRequest> json_request_;
    std::optional<std::vector<uint8_t>> decoded_ciphertext_;
};

// Decryption API response wrapper
class DecryptApiResponse : public ApiResponse {
public:
    // Returns the decrypted value as binary data (decoded from base64)
    span<const uint8_t> GetResponsePlaintext() const;
    
    const DecryptJsonResponse& GetResponseAttributes() const;

public:
    // Setters for decryption-specific response
    void SetJsonResponse(const DecryptJsonResponse& response);
    void SetJsonRequest(const DecryptJsonRequest& request);

protected:
    // Getters for decryption-specific response (override protected base methods)
    const DecryptJsonResponse& GetJsonResponse() const override;
    bool HasJsonResponse() const override;
    
    // Check and get methods for decryption-specific request (override virtual base methods)
    bool HasJsonRequest() const override;
    const JsonRequest& GetJsonRequest() const override;
    
    std::optional<DecryptJsonResponse> decrypt_response_;
    std::optional<DecryptJsonRequest> json_request_;
    std::optional<std::vector<uint8_t>> decoded_plaintext_;
};

/**
 * API Client for DataBatchProtectionService
 * Provides a library level interface for making HTTP calls to the DBPS API server
 */
class DBPSApiClient {
public:
    /**
     * Constructor gets implementation of a HTTP client.
     * The HTTP client is expected to be thread-safe.
     * @param http_client Custom HTTP client implementation
     */
    explicit DBPSApiClient(std::shared_ptr<HttpClientInterface> http_client);
    
    /**
     * Destructor
     */
    ~DBPSApiClient() = default;
    
    /**
     * Health check endpoint
     * @return Response string from the health check
     * @throws std::runtime_error if the request fails
     */
    std::string HealthCheck();
    
    /**
     * Encryption endpoint - encrypts the provided plaintext using the given context and serialization parameters
     * 
     * @param plaintext Binary data to be encrypted, provided as a span of bytes
     * @param column_name Name of the database column for which this data is being encrypted
     * @param datatype The data type of the plaintext (e.g., BYTE_ARRAY, STRING, etc.)
     * @param compression Compression algorithm used to compress the plaintext before this call (format of the input)
     * @param format Data format specification (currently only RAW_C_DATA is supported)
     * @param encrypted_compression Compression algorithm to be used to compress the encrypted data (format of the output)
     * @param key_id Identifier for the encryption key to be used (not the key itself)
     * @param user_id Identifier for the user requesting the encryption
     * 
     * @return The encryption API response object containing comprehensive information about the call
     * 
     * @note Currently only RAW_C_DATA format is supported
     */
    EncryptApiResponse Encrypt(
        span<const uint8_t> plaintext,
        const std::string& column_name,
        Type::type datatype,
        CompressionCodec::type compression,
        Format::type format,
        CompressionCodec::type encrypted_compression,
        const std::string& key_id,
        const std::string& user_id
    );
    
    /**
     * Decryption endpoint - decrypts the provided ciphertext using the given context and serialization parameters
     * 
     * @param ciphertext Binary encrypted data to be decrypted, provided as a span of bytes
     * @param column_name Name of the database column for which this data is being decrypted
     * @param datatype The data type of the original plaintext (e.g., BYTE_ARRAY, STRING, etc.)
     * @param compression Compression algorithm used to compress the encrypted data before this call (format of the input)
     * @param format Data format specification (currently only RAW_C_DATA is supported)
     * @param encrypted_compression Compression algorithm to be used to compress the decrypted data (format of the output)
     * @param key_id Identifier for the encryption key to be used for decryption (not the key itself)
     * @param user_id Identifier for the user requesting the decryption
     * 
     * @return The decryption API response object containing comprehensive information about the call
     * 
     * @note Currently only RAW_C_DATA format is supported
     */
    DecryptApiResponse Decrypt(
        span<const uint8_t> ciphertext,
        const std::string& column_name,
        Type::type datatype,
        CompressionCodec::type compression,
        Format::type format,
        CompressionCodec::type encrypted_compression,
        const std::string& key_id,
        const std::string& user_id
    );

private:
    const std::shared_ptr<HttpClientInterface> http_client_;
};
