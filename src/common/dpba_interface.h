#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <utility>

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

namespace dbps::external {

// Intentionally similar to parquet::Type
struct Type {
    enum type {
        BOOLEAN = 0,
        INT32 = 1,
        INT64 = 2,
        INT96 = 3,
        FLOAT = 4,
        DOUBLE = 5,
        BYTE_ARRAY = 6,
        FIXED_LEN_BYTE_ARRAY = 7
    };
};

// Intentionally similar to arrow::CompressionCodec
struct CompressionCodec {
    enum type {
        UNCOMPRESSED = 0,
        SNAPPY = 1,
        GZIP = 2,
        LZO = 3,
        BROTLI = 4,
        LZ4 = 5,
        ZSTD = 6,
        LZ4_RAW = 7
    };
};

// ++++ To docs:
// - While handle to EncryptionResult exists, ciphertext() is guaranteed to return the result.
// - Read operations are not destructive.
// - Destructor should dispose of internal memory (either by delegation or by destruction).
// - No throwing exceptions.
class DBPS_EXPORT EncryptionResult {
public:
    virtual std::span<uint8_t> ciphertext() = 0;

    // Allows a larger backing buffer than the exact ciphertext size.
    virtual int size() = 0;

    // Success flag; false indicates an error.
    virtual bool success() const = 0;

    // Error details (valid when success() == false).
    virtual const std::string& error_message() const = 0;
    virtual const std::map<std::string, std::string>& error_fields() const = 0;

    virtual ~EncryptionResult() = default;
};

class DBPS_EXPORT DecryptionResult {
public:
    virtual std::span<uint8_t> plaintext() = 0;

    // Allows a larger backing buffer than the exact ciphertext size.
    virtual int size() = 0;

    // Success flag; false indicates an error.
    virtual bool success() const = 0;

    // Error details (valid when success() == false).
    virtual const std::string& error_message() const = 0;
    virtual const std::map<std::string, std::string>& error_fields() const = 0;

    virtual ~DecryptionResult() = default;
};

class DBPS_EXPORT DataBatchProtectionAgentInterface {
public:
    DataBatchProtectionAgentInterface() = default;

    // user_id is not stored as a member, but it is expected to be in the app_context map.
    void init(
        std::string column_name,
        std::map<std::string, std::string> connection_config,
        std::string app_context,
        std::string column_key_id,
        Type::type data_type,
        CompressionCodec::type compression_type)
    {
        column_name_ = std::move(column_name);
        connection_config_ = std::move(connection_config);
        app_context_ = std::move(app_context);
        column_key_id_ = std::move(column_key_id);
        data_type_ = data_type;
        compression_type_ = compression_type;
    }

    virtual std::unique_ptr<EncryptionResult> Encrypt(
        std::span<const uint8_t> plaintext) = 0;

    virtual std::unique_ptr<DecryptionResult> Decrypt(
        std::span<const uint8_t> ciphertext) = 0;

    virtual ~DataBatchProtectionAgentInterface() = default;

private:
    std::string column_name_;
    std::map<std::string, std::string> connection_config_;
    std::string app_context_;  // includes user_id

    std::string column_key_id_;
    Type::type data_type_;
    CompressionCodec::type compression_type_;
};
}
