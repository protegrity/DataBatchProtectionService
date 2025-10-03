#include <iostream>
#include <string>
#include <cassert>
#include <crow/app.h>
#include "json_request.h"
#include "enums.h"

using namespace dbps::external;

// Forward declarations for internal functions from json_request.cpp
std::optional<std::string> SafeGetFromJsonPath(const crow::json::rvalue& json_body, const std::vector<std::string>& path);
std::optional<int> SafeParseToInt(const std::string& str);

// Test-specific derived class to access protected methods
class TestableJsonRequest : public JsonRequest {
public:
    // Implement the pure virtual method for testing
    void Parse(const std::string& request_body) override {
        ParseCommon(request_body);
    }
    
    // Implement the pure virtual ToJsonString method for testing
    std::string ToJsonString() const override {
        crow::json::wvalue json;
        json["test"] = "testable_request";
        return json.dump();
    }
};

// Test-specific derived class for JsonResponse base class testing
class TestableJsonResponse : public JsonResponse {
public:
    // Implement the pure virtual ToJsonString method for testing
    std::string ToJsonString() const override {
        crow::json::wvalue json;
        json["test"] = "testable_response";
        return json.dump();
    }
};

// Simple test framework
#define TEST(name) void test_##name()
#define ASSERT(condition) assert(condition)
#define ASSERT_EQ(expected, actual) assert((expected) == (actual))
#define ASSERT_TRUE(condition) assert(condition)
#define ASSERT_FALSE(condition) assert(!(condition))

// Test utilities
void PrintTestResult(const std::string& test_name, bool passed) {
    std::cout << (passed ? "PASS" : "FAIL") << ": " << test_name << std::endl;
}

// Test data
const std::string VALID_ENCRYPT_JSON = R"({
    "column_reference": {
        "name": "email"
    },
    "data_batch": {
        "datatype_info": {
            "datatype": "BYTE_ARRAY"
        },
        "value": "dGVzdEBleGFtcGxlLmNvbQ==",
        "value_format": {
            "compression": "UNCOMPRESSED",
            "format": "UNDEFINED"
        }
    },
    "data_batch_encrypted": {
        "value_format": {
            "compression": "GZIP"
        }
    },
    "encryption": {
        "key_id": "key123"
    },
    "access": {
        "user_id": "user456"
    },
    "debug": {
        "reference_id": "ref789",
        "pretty_printed_value": "test@example.com"
    }
})";

const std::string VALID_DECRYPT_JSON = R"({
    "column_reference": {
        "name": "email"
    },
    "data_batch": {
        "datatype_info": {
            "datatype": "BYTE_ARRAY"
        },
        "value_format": {
            "compression": "UNCOMPRESSED",
            "format": "UNDEFINED"
        }
    },
    "data_batch_encrypted": {
        "value": "RU5DUllQVEVEX3Rlc3RAZXhhbXBsZS5jb20=",
        "value_format": {
            "compression": "GZIP"
        }
    },
    "encryption": {
        "key_id": "key123"
    },
    "access": {
        "user_id": "user456"
    },
    "debug": {
        "reference_id": "ref789",
        "pretty_printed_value": "ENCRYPTED_test@example.com"
    }
})";

// Test cases for JsonRequest base class
TEST(JsonRequestValidParse) {
    EncryptJsonRequest request;
    request.Parse(VALID_ENCRYPT_JSON);
    
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ(Type::BYTE_ARRAY, request.datatype_.value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, request.compression_.value());
    ASSERT_EQ(Format::UNDEFINED, request.format_.value());
    ASSERT_EQ(CompressionCodec::GZIP, request.encrypted_compression_.value());
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_EQ("ref789", request.reference_id_);
    
    // Check encrypt-specific field
    ASSERT_EQ("dGVzdEBleGFtcGxlLmNvbQ==", request.value_); // "test@example.com"
    
    ASSERT_TRUE(request.IsValid());
    ASSERT_EQ("", request.GetValidationError());
}

TEST(JsonRequestMissingRequiredFields) {
    const std::string incomplete_json = R"({
        "column_reference": {
            "name": "email"
        }
    })";
    
    EncryptJsonRequest request;
    request.Parse(incomplete_json);
    
    ASSERT_EQ("email", request.column_name_);
    ASSERT_FALSE(request.datatype_.has_value());
    ASSERT_FALSE(request.compression_.has_value());
    ASSERT_FALSE(request.format_.has_value());
    ASSERT_FALSE(request.encrypted_compression_.has_value());
    ASSERT_EQ("", request.key_id_);
    ASSERT_EQ("", request.user_id_);
    ASSERT_EQ("", request.reference_id_);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("Missing required fields:") != std::string::npos);
    ASSERT_TRUE(error.find("data_batch.datatype_info.datatype") != std::string::npos);
    ASSERT_TRUE(error.find("encryption.key_id") != std::string::npos);
}

TEST(JsonRequestInvalidJson) {
    const std::string invalid_json = "{ invalid json }";
    
    EncryptJsonRequest request;
    request.Parse(invalid_json);
    
    // All fields should remain empty/default
    ASSERT_EQ("", request.column_name_);
    ASSERT_FALSE(request.datatype_.has_value());
    ASSERT_FALSE(request.compression_.has_value());
    ASSERT_FALSE(request.format_.has_value());
    ASSERT_FALSE(request.encrypted_compression_.has_value());
    ASSERT_EQ("", request.key_id_);
    ASSERT_EQ("", request.user_id_);
    ASSERT_EQ("", request.reference_id_);
    
    ASSERT_FALSE(request.IsValid());
}

TEST(JsonRequestRequiredReferenceIdMissing) {
    const std::string json_without_ref = R"({
        "column_reference": {
            "name": "email"
        },
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "UNDEFINED"
            }
        },
        "data_batch_encrypted": {
            "value_format": {
                "compression": "GZIP"
            }
        },
        "encryption": {
            "key_id": "key123"
        },
        "access": {
            "user_id": "user456"
        }
    })";
    
    EncryptJsonRequest request;
    request.Parse(json_without_ref);
    
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ(Type::BYTE_ARRAY, request.datatype_.value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, request.compression_.value());
    ASSERT_EQ(Format::UNDEFINED, request.format_.value());
    ASSERT_EQ(CompressionCodec::GZIP, request.encrypted_compression_.value());
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_EQ("", request.reference_id_);
    
    // Check encrypt-specific field (should be empty since no value in JSON)
    ASSERT_EQ("", request.value_);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("debug.reference_id") != std::string::npos);
}

// Test cases for EncryptJsonRequest
TEST(EncryptJsonRequestValidParse) {
    EncryptJsonRequest request;
    request.Parse(VALID_ENCRYPT_JSON);
    
    // Check common fields
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ(Type::BYTE_ARRAY, request.datatype_.value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, request.compression_.value());
    ASSERT_EQ(Format::UNDEFINED, request.format_.value());
    ASSERT_EQ(CompressionCodec::GZIP, request.encrypted_compression_.value());
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_EQ("ref789", request.reference_id_);
    
    // Check encrypt-specific fields
    ASSERT_EQ("dGVzdEBleGFtcGxlLmNvbQ==", request.value_); // "test@example.com"
    
    ASSERT_TRUE(request.IsValid());
    ASSERT_EQ("", request.GetValidationError());
}

TEST(EncryptJsonRequestMissingValue) {
    const std::string json_without_value = R"({
        "column_reference": {
            "name": "email"
        },
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "UNDEFINED"
            }
        },
        "data_batch_encrypted": {
            "value_format": {
                "compression": "GZIP"
            }
        },
        "encryption": {
            "key_id": "key123"
        },
        "access": {
            "user_id": "user456"
        },
        "debug": {
            "reference_id": "ref789",
            "encrypted_value_plaintext": "ENCRYPTED_test@example.com"
        }
    })";
    
    EncryptJsonRequest request;
    request.Parse(json_without_value);
    
    // Common fields should be parsed
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ(Type::BYTE_ARRAY, request.datatype_.value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, request.compression_.value());
    ASSERT_EQ(Format::UNDEFINED, request.format_.value());
    ASSERT_EQ(CompressionCodec::GZIP, request.encrypted_compression_.value());
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_EQ("ref789", request.reference_id_);
    
    // Encrypt-specific field should be empty
    ASSERT_EQ("", request.value_);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("Missing required field: data_batch.value") != std::string::npos);
}

// Test cases for DecryptJsonRequest
TEST(DecryptJsonRequestValidParse) {
    DecryptJsonRequest request;
    request.Parse(VALID_DECRYPT_JSON);
    
    // Check common fields
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ(Type::BYTE_ARRAY, request.datatype_.value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, request.compression_.value());
    ASSERT_EQ(Format::UNDEFINED, request.format_.value());
    ASSERT_EQ(CompressionCodec::GZIP, request.encrypted_compression_.value());
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_EQ("ref789", request.reference_id_);
    
    // Check decrypt-specific fields
    ASSERT_EQ("RU5DUllQVEVEX3Rlc3RAZXhhbXBsZS5jb20=", request.encrypted_value_); // "ENCRYPTED_test@example.com"
    
    ASSERT_TRUE(request.IsValid());
    ASSERT_EQ("", request.GetValidationError());
}

TEST(DecryptJsonRequestMissingEncryptedValue) {
    const std::string json_without_encrypted_value = R"({
        "column_reference": {
            "name": "email"
        },
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "UNDEFINED"
            }
        },
        "data_batch_encrypted": {
            "value_format": {
                "compression": "GZIP"
            }
        },
        "encryption": {
            "key_id": "key123"
        },
        "access": {
            "user_id": "user456"
        },
        "debug": {
            "reference_id": "ref789",
            "encrypted_value_plaintext": "ENCRYPTED_test@example.com"
        }
    })";
    
    DecryptJsonRequest request;
    request.Parse(json_without_encrypted_value);
    
    // Common fields should be parsed
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ(Type::BYTE_ARRAY, request.datatype_.value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, request.compression_.value());
    ASSERT_EQ(Format::UNDEFINED, request.format_.value());
    ASSERT_EQ(CompressionCodec::GZIP, request.encrypted_compression_.value());
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_EQ("ref789", request.reference_id_);
    
    // Decrypt-specific field should be empty
    ASSERT_EQ("", request.encrypted_value_);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("Missing required field: data_batch_encrypted.value") != std::string::npos);
}

// Test SafeGetFromJsonPath functionality
TEST(SafeGetFromJsonPathValid) {
    auto json_body = crow::json::load(VALID_ENCRYPT_JSON);
    ASSERT_TRUE(json_body);
    
    auto result = SafeGetFromJsonPath(json_body, {"column_reference", "name"});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ("email", *result);
    
    result = SafeGetFromJsonPath(json_body, {"data_batch", "value"});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ("dGVzdEBleGFtcGxlLmNvbQ==", *result); // "test@example.com"
}

TEST(SafeGetFromJsonPathInvalidPath) {
    auto json_body = crow::json::load(VALID_ENCRYPT_JSON);
    ASSERT_TRUE(json_body);
    
    auto result = SafeGetFromJsonPath(json_body, {"nonexistent", "field"});
    ASSERT_FALSE(result.has_value());
    
    result = SafeGetFromJsonPath(json_body, {"column_reference", "nonexistent"});
    ASSERT_FALSE(result.has_value());
}

// Test JSON generation functionality
TEST(EncryptJsonRequestToJson) {
    EncryptJsonRequest request;
    request.Parse(VALID_ENCRYPT_JSON);
    
    ASSERT_TRUE(request.IsValid());
    
    // Generate JSON from the parsed object
    std::string json_string = request.ToJson();
    
    // Verify the generated JSON contains expected fields
    ASSERT_TRUE(json_string.find("email") != std::string::npos);
    ASSERT_TRUE(json_string.find("dGVzdEBleGFtcGxlLmNvbQ==") != std::string::npos); // "test@example.com"
    ASSERT_TRUE(json_string.find("ref789") != std::string::npos);
    ASSERT_TRUE(json_string.find("key123") != std::string::npos);
    ASSERT_TRUE(json_string.find("user456") != std::string::npos);
}

TEST(EncryptJsonRequestWithEncodingAttributes) {
    const std::string json_with_encoding_attrs = R"({
        "column_reference": {
            "name": "email"
        },
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value": "dGVzdEBleGFtcGxlLmNvbQ==",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN",
                "encoding_attributes": {
                    "page_type": "DATA_PAGE",
                    "page_encoding": "PLAIN",
                    "data_page_num_values": "1"
                }
            }
        },
        "data_batch_encrypted": {
            "value_format": {
                "compression": "GZIP"
            }
        },
        "encryption": {
            "key_id": "key123"
        },
        "access": {
            "user_id": "user456"
        },
        "debug": {
            "reference_id": "ref789"
        }
    })";
    
    EncryptJsonRequest request;
    request.Parse(json_with_encoding_attrs);
    
    // Verify common fields are parsed correctly
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ(Type::BYTE_ARRAY, request.datatype_.value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, request.compression_.value());
    ASSERT_EQ(Format::PLAIN, request.format_.value());
    ASSERT_EQ(CompressionCodec::GZIP, request.encrypted_compression_.value());
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_EQ("ref789", request.reference_id_);
    ASSERT_EQ("dGVzdEBleGFtcGxlLmNvbQ==", request.value_);
    
    // Verify encoding_attributes are parsed correctly
    ASSERT_EQ(3, request.encoding_attributes_.size());
    ASSERT_EQ("DATA_PAGE", request.encoding_attributes_["page_type"]);
    ASSERT_EQ("PLAIN", request.encoding_attributes_["page_encoding"]);
    ASSERT_EQ("1", request.encoding_attributes_["data_page_num_values"]);
    
    ASSERT_TRUE(request.IsValid());
}

TEST(EncryptJsonRequestToJsonWithEncodingAttributes) {
    EncryptJsonRequest request;
    
    // Set up request with encoding_attributes
    request.column_name_ = "email";
    request.datatype_ = Type::BYTE_ARRAY;
    request.compression_ = CompressionCodec::UNCOMPRESSED;
    request.format_ = Format::PLAIN;
    request.encrypted_compression_ = CompressionCodec::GZIP;
    request.key_id_ = "key123";
    request.user_id_ = "user456";
    request.reference_id_ = "ref789";
    request.value_ = "dGVzdEBleGFtcGxlLmNvbQ==";
    
    // Add encoding_attributes
    request.encoding_attributes_["page_type"] = "DATA_PAGE";
    request.encoding_attributes_["page_encoding"] = "PLAIN";
    request.encoding_attributes_["data_page_num_values"] = "1";
    
    ASSERT_TRUE(request.IsValid());
    
    // Generate JSON from the parsed object
    std::string json_string = request.ToJson();
    
    // Verify the generated JSON contains expected fields
    ASSERT_TRUE(json_string.find("email") != std::string::npos);
    ASSERT_TRUE(json_string.find("dGVzdEBleGFtcGxlLmNvbQ==") != std::string::npos);
    ASSERT_TRUE(json_string.find("ref789") != std::string::npos);
    ASSERT_TRUE(json_string.find("key123") != std::string::npos);
    ASSERT_TRUE(json_string.find("user456") != std::string::npos);
    
    // Verify encoding_attributes are serialized correctly
    ASSERT_TRUE(json_string.find("encoding_attributes") != std::string::npos);
    ASSERT_TRUE(json_string.find("page_type") != std::string::npos);
    ASSERT_TRUE(json_string.find("DATA_PAGE") != std::string::npos);
    ASSERT_TRUE(json_string.find("page_encoding") != std::string::npos);
    ASSERT_TRUE(json_string.find("PLAIN") != std::string::npos);
    ASSERT_TRUE(json_string.find("data_page_num_values") != std::string::npos);
    ASSERT_TRUE(json_string.find("\"1\"") != std::string::npos);
}

TEST(DecryptJsonRequestToJson) {
    DecryptJsonRequest request;
    request.Parse(VALID_DECRYPT_JSON);
    
    ASSERT_TRUE(request.IsValid());
    
    // Generate JSON from the parsed object
    std::string json_string = request.ToJson();
    
    // Verify the generated JSON contains expected fields
    ASSERT_TRUE(json_string.find("email") != std::string::npos);
    ASSERT_TRUE(json_string.find("RU5DUllQVEVEX3Rlc3RAZXhhbXBsZS5jb20=") != std::string::npos); // "ENCRYPTED_test@example.com"
    ASSERT_TRUE(json_string.find("ref789") != std::string::npos);
    ASSERT_TRUE(json_string.find("key123") != std::string::npos);
    ASSERT_TRUE(json_string.find("user456") != std::string::npos);
}

// Test data for JsonResponse parsing
const std::string VALID_ENCRYPT_RESPONSE_JSON = R"({
    "data_batch_encrypted": {
        "value_format": {
            "compression": "GZIP"
        },
        "value": "RU5DUllQVEVEX3Rlc3RAZXhhbXBsZS5jb20="
    },
    "access": {
        "user_id": "user456",
        "role": "admin",
        "access_control": "read_write"
    },
    "debug": {
        "reference_id": "ref789",
        "pretty_printed_value": "ENCRYPTED_test@example.com"
    }
})";

const std::string VALID_DECRYPT_RESPONSE_JSON = R"({
    "data_batch": {
        "datatype_info": {
            "datatype": "BYTE_ARRAY"
        },
        "value": "dGVzdEBleGFtcGxlLmNvbQ==",
        "value_format": {
            "compression": "UNCOMPRESSED",
            "format": "UNDEFINED"
        }
    },
    "access": {
        "user_id": "user456",
        "role": "admin",
        "access_control": "read_write"
    },
    "debug": {
        "reference_id": "ref789",
        "pretty_printed_value": "test@example.com"
    }
})";

// Test cases for JsonResponse parsing
TEST(EncryptJsonResponseValidParse) {
    EncryptJsonResponse response;
    response.Parse(VALID_ENCRYPT_RESPONSE_JSON);
    
    ASSERT_EQ("user456", response.user_id_);
    ASSERT_EQ("admin", response.role_);
    ASSERT_EQ("read_write", response.access_control_);
    ASSERT_EQ("ref789", response.reference_id_);
    ASSERT_EQ(CompressionCodec::GZIP, response.encrypted_compression_.value());
    ASSERT_EQ("RU5DUllQVEVEX3Rlc3RAZXhhbXBsZS5jb20=", response.encrypted_value_); // "ENCRYPTED_test@example.com"
    
    ASSERT_TRUE(response.IsValid());
    ASSERT_EQ("", response.GetValidationError());
}

TEST(DecryptJsonResponseValidParse) {
    DecryptJsonResponse response;
    response.Parse(VALID_DECRYPT_RESPONSE_JSON);
    
    ASSERT_EQ("user456", response.user_id_);
    ASSERT_EQ("admin", response.role_);
    ASSERT_EQ("read_write", response.access_control_);
    ASSERT_EQ("ref789", response.reference_id_);
    ASSERT_EQ(Type::BYTE_ARRAY, response.datatype_.value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, response.compression_.value());
    ASSERT_EQ(Format::UNDEFINED, response.format_.value());
    ASSERT_EQ("dGVzdEBleGFtcGxlLmNvbQ==", response.decrypted_value_); // "test@example.com"
    
    ASSERT_TRUE(response.IsValid());
    ASSERT_EQ("", response.GetValidationError());
}

TEST(JsonResponseInvalidJson) {
    EncryptJsonResponse response;
    response.Parse("invalid json");
    
    // Should handle invalid JSON gracefully
    ASSERT_FALSE(response.IsValid());
}

// JsonResponse test cases
TEST(JsonResponseMissingRequiredFields) {
    TestableJsonResponse response;
    response.Parse("{}"); // Empty JSON
    
    ASSERT_FALSE(response.IsValid());
    std::string error = response.GetValidationError();
    ASSERT_TRUE(error.find("access.user_id") != std::string::npos);
    ASSERT_TRUE(error.find("access.role") != std::string::npos);
    ASSERT_TRUE(error.find("access.access_control") != std::string::npos);
    ASSERT_TRUE(error.find("debug.reference_id") != std::string::npos);
}

TEST(EncryptJsonResponseMissingEncryptedValue) {
    EncryptJsonResponse response;
    response.Parse(R"({
        "access": {"user_id": "user123", "role": "admin", "access_control": "read"},
        "debug": {"reference_id": "ref456"},
        "data_batch_encrypted": {"value_format": {"compression": "GZIP"}}
    })");
    
    ASSERT_FALSE(response.IsValid());
    ASSERT_TRUE(response.GetValidationError().find("data_batch_encrypted.value") != std::string::npos);
}

TEST(DecryptJsonResponseMissingDecryptedValue) {
    DecryptJsonResponse response;
    response.Parse(R"({
        "access": {"user_id": "user123", "role": "admin", "access_control": "read"},
        "debug": {"reference_id": "ref456"},
        "data_batch": {
            "datatype_info": {
                "datatype": "BYTE_ARRAY"
            },
            "value_format": {"compression": "UNCOMPRESSED", "format": "UNDEFINED"}
        }
    })");
    
    ASSERT_FALSE(response.IsValid());
    ASSERT_TRUE(response.GetValidationError().find("data_batch.value") != std::string::npos);
}

TEST(EncryptJsonResponseMissingEncryptedCompression) {
    EncryptJsonResponse response;
    response.Parse(R"({
        "access": {"user_id": "user123", "role": "admin", "access_control": "read"},
        "debug": {"reference_id": "ref456"},
        "data_batch_encrypted": {"value": "RU5DUllQVEVEX2RhdGE="} // "ENCRYPTED_data"
    })");
    
    ASSERT_FALSE(response.IsValid());
    ASSERT_TRUE(response.GetValidationError().find("data_batch_encrypted.value_format.compression") != std::string::npos);
}

TEST(DecryptJsonResponseMissingDatatype) {
    DecryptJsonResponse response;
    // value is "decrypted_data"
    response.Parse(R"({
        "access": {"user_id": "user123", "role": "admin", "access_control": "read"},
        "debug": {"reference_id": "ref456"},
        "data_batch": {
            "value": "ZGVjcnlwdGVkX2RhdGE=",
            "value_format": {"compression": "UNCOMPRESSED", "format": "UNDEFINED"}
        }
    })");
    
    ASSERT_FALSE(response.IsValid());
    ASSERT_TRUE(response.GetValidationError().find("data_batch.datatype_info.datatype") != std::string::npos);
}

TEST(EncryptJsonResponseToJson) {
    EncryptJsonResponse response;
    response.user_id_ = "user123";
    response.role_ = "admin";
    response.access_control_ = "read_write";
    response.reference_id_ = "ref456";
    response.encrypted_compression_ = CompressionCodec::GZIP;
    response.encrypted_value_ = "RU5DUllQVEVEX2RhdGE="; // "ENCRYPTED_data"
    
    ASSERT_TRUE(response.IsValid());
    
    std::string json_string = response.ToJson();
    ASSERT_TRUE(json_string.find("user123") != std::string::npos);
    ASSERT_TRUE(json_string.find("admin") != std::string::npos);
    ASSERT_TRUE(json_string.find("read_write") != std::string::npos);
    ASSERT_TRUE(json_string.find("ref456") != std::string::npos);
    ASSERT_TRUE(json_string.find("RU5DUllQVEVEX2RhdGE=") != std::string::npos); // "ENCRYPTED_data"
    ASSERT_TRUE(json_string.find("GZIP") != std::string::npos);
}

TEST(DecryptJsonResponseToJson) {
    DecryptJsonResponse response;
    response.user_id_ = "user123";
    response.role_ = "admin";
    response.access_control_ = "read_write";
    response.reference_id_ = "ref456";
    response.datatype_ = Type::BYTE_ARRAY;
    response.compression_ = CompressionCodec::UNCOMPRESSED;
    response.format_ = Format::UNDEFINED;
    response.decrypted_value_ = "ZGVjcnlwdGVkX2RhdGE="; // "decrypted_data"
    
    ASSERT_TRUE(response.IsValid());
    
    std::string json_string = response.ToJson();
    ASSERT_TRUE(json_string.find("user123") != std::string::npos);
    ASSERT_TRUE(json_string.find("admin") != std::string::npos);
    ASSERT_TRUE(json_string.find("read_write") != std::string::npos);
    ASSERT_TRUE(json_string.find("ref456") != std::string::npos);
    ASSERT_TRUE(json_string.find("ZGVjcnlwdGVkX2RhdGE=") != std::string::npos); // "decrypted_data"
    ASSERT_TRUE(json_string.find("BYTE_ARRAY") != std::string::npos);
    ASSERT_TRUE(json_string.find("UNCOMPRESSED") != std::string::npos);
    ASSERT_TRUE(json_string.find("UNDEFINED") != std::string::npos);
}

TEST(JsonResponsePartialParsing) {
    EncryptJsonResponse response;
    // value is "ENCRYPTED_data"
    response.Parse(R"({
        "access": {"user_id": "user123"},
        "data_batch_encrypted": {"value": "RU5DUllQVEVEX2RhdGE="}
    })");
    
    // Should parse what it can, but validation should fail
    ASSERT_EQ("user123", response.user_id_);
    ASSERT_EQ("RU5DUllQVEVEX2RhdGE=", response.encrypted_value_); // "ENCRYPTED_data"
    ASSERT_FALSE(response.IsValid()); // Missing other required fields
}

TEST(JsonResponseEmptyStringHandling) {
    EncryptJsonResponse response;
    response.Parse("");
    
    ASSERT_FALSE(response.IsValid());
    // Should handle gracefully without crashing
}

TEST(JsonResponseNullJsonHandling) {
    EncryptJsonResponse response;
    response.Parse("null");
    
    ASSERT_FALSE(response.IsValid());
    // Should handle gracefully without crashing
}

// Test datatype_length functionality - simplified
static void test_DatatypeLengthParsing() {
    // Test parsing with datatype_length
    const std::string json_with_datatype_length = R"({
        "column_reference": {
            "name": "email"
        },
        "data_batch": {
            "datatype_info": {
                "datatype": "FIXED_LEN_BYTE_ARRAY",
                "length": 16
            },
            "value": "SGVsbG8sIFdvcmxkIQ==",
            "value_format": {
                "compression": "UNCOMPRESSED",
                "format": "PLAIN"
            }
        },
        "data_batch_encrypted": {
            "value_format": {
                "compression": "UNCOMPRESSED"
            }
        },
        "encryption": {
            "key_id": "test_key_123"
        },
        "access": {
            "user_id": "test_user"
        },
        "debug": {
            "reference_id": "test_ref_123"
        }
    })";
    
    EncryptJsonRequest request;
    request.Parse(json_with_datatype_length);
    
    ASSERT_TRUE(request.IsValid());
    ASSERT_TRUE(request.datatype_length_.has_value());
    ASSERT_EQ(request.datatype_length_.value(), 16);
}

// Test-specific derived class for EncryptJsonRequest testing
class TestableEncryptJsonRequest : public EncryptJsonRequest {
public:
    // Make ToJsonString public for testing
    std::string ToJsonString() const override {
        return EncryptJsonRequest::ToJsonString();
    }
};

static void test_DatatypeLengthSerialization() {
    // Test serialization with and without datatype_length
    TestableEncryptJsonRequest request;
    request.user_id_ = "test_user";
    request.reference_id_ = "test_ref_123";
    request.datatype_ = Type::FIXED_LEN_BYTE_ARRAY;
    request.datatype_length_ = 16;
    request.compression_ = CompressionCodec::UNCOMPRESSED;
    request.format_ = Format::PLAIN;
    request.encrypted_compression_ = CompressionCodec::UNCOMPRESSED;
    request.key_id_ = "test_key_123";
    request.value_ = "SGVsbG8sIFdvcmxkIQ==";
    
    std::string json_output = request.ToJsonString();
    auto json_obj = crow::json::load(json_output);
    ASSERT_TRUE(json_obj["data_batch"]["datatype_info"].has("length"));
    ASSERT_EQ(json_obj["data_batch"]["datatype_info"]["length"], 16);
}

// Test invalid datatype_length values
static void test_JsonRequestInvalidDatatypeLength() {
    const std::string json_with_invalid_datatype_length = R"({
        "column_reference": {"name": "email"},
        "data_batch": {
            "datatype_info": {
                "datatype": "FIXED_LEN_BYTE_ARRAY",
                "length": "not_a_number"
            },
            "value_format": {"compression": "UNCOMPRESSED", "format": "UNDEFINED"}
        },
        "data_batch_encrypted": {"value_format": {"compression": "GZIP"}},
        "encryption": {"key_id": "key123"},
        "access": {"user_id": "user456"},
        "debug": {"reference_id": "ref789"}
    })";
    
    EncryptJsonRequest request;
    request.Parse(json_with_invalid_datatype_length);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("data_batch.datatype_info.length (invalid integer value)") != std::string::npos);
}

static void test_DecryptJsonResponseInvalidDatatypeLength() {
    const std::string json_with_invalid_datatype_length = R"({
        "access": {"user_id": "user123", "role": "admin", "access_control": "full"},
        "debug": {"reference_id": "ref456"},
        "data_batch": {
            "datatype_info": {
                "datatype": "FIXED_LEN_BYTE_ARRAY",
                "length": "invalid_int"
            },
            "value_format": {"compression": "UNCOMPRESSED", "format": "UNDEFINED"},
            "value": "decrypted_data"
        }
    })";
    
    DecryptJsonResponse response;
    response.Parse(json_with_invalid_datatype_length);
    
    ASSERT_FALSE(response.IsValid());
    std::string error = response.GetValidationError();
    ASSERT_TRUE(error.find("data_batch.datatype_info.length (invalid integer value)") != std::string::npos);
}

// Main test runner
int main() {
    std::cout << "Running JSON Request Tests..." << std::endl;
    std::cout << "==================================" << std::endl;
    
    bool all_tests_passed = true;
    
    // Run all tests
    try {
        test_JsonRequestValidParse();
        PrintTestResult("JsonRequest valid parse", true);
    } catch (...) {
        PrintTestResult("JsonRequest valid parse", false);
        all_tests_passed = false;
    }
    
    try {
        test_JsonRequestMissingRequiredFields();
        PrintTestResult("JsonRequest missing required fields", true);
    } catch (...) {
        PrintTestResult("JsonRequest missing required fields", false);
        all_tests_passed = false;
    }
    
    try {
        test_JsonRequestInvalidJson();
        PrintTestResult("JsonRequest invalid JSON", true);
    } catch (...) {
        PrintTestResult("JsonRequest invalid JSON", false);
        all_tests_passed = false;
    }
    
    try {
        test_JsonRequestRequiredReferenceIdMissing();
        PrintTestResult("JsonRequest required reference_id missing", true);
    } catch (...) {
        PrintTestResult("JsonRequest required reference_id missing", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptJsonRequestValidParse();
        PrintTestResult("EncryptJsonRequest valid parse", true);
    } catch (...) {
        PrintTestResult("EncryptJsonRequest valid parse", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptJsonRequestMissingValue();
        PrintTestResult("EncryptJsonRequest missing value", true);
    } catch (...) {
        PrintTestResult("EncryptJsonRequest missing value", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptJsonRequestValidParse();
        PrintTestResult("DecryptJsonRequest valid parse", true);
    } catch (...) {
        PrintTestResult("DecryptJsonRequest valid parse", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptJsonRequestMissingEncryptedValue();
        PrintTestResult("DecryptJsonRequest missing encrypted value", true);
    } catch (...) {
        PrintTestResult("DecryptJsonRequest missing encrypted value", false);
        all_tests_passed = false;
    }
    
    try {
        test_SafeGetFromJsonPathValid();
        PrintTestResult("SafeGetFromJsonPath valid", true);
    } catch (...) {
        PrintTestResult("SafeGetFromJsonPath valid", false);
        all_tests_passed = false;
    }
    
    try {
        test_SafeGetFromJsonPathInvalidPath();
        PrintTestResult("SafeGetFromJsonPath invalid path", true);
    } catch (...) {
        PrintTestResult("SafeGetFromJsonPath invalid path", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptJsonRequestToJson();
        PrintTestResult("EncryptJsonRequest ToJson", true);
    } catch (...) {
        PrintTestResult("EncryptJsonRequest ToJson", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptJsonRequestWithEncodingAttributes();
        PrintTestResult("EncryptJsonRequest with encoding attributes", true);
    } catch (...) {
        PrintTestResult("EncryptJsonRequest with encoding attributes", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptJsonRequestToJsonWithEncodingAttributes();
        PrintTestResult("EncryptJsonRequest ToJson with encoding attributes", true);
    } catch (...) {
        PrintTestResult("EncryptJsonRequest ToJson with encoding attributes", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptJsonRequestToJson();
        PrintTestResult("DecryptJsonRequest ToJson", true);
    } catch (...) {
        PrintTestResult("DecryptJsonRequest ToJson", false);
        all_tests_passed = false;
    }
    
    try {
        test_EncryptJsonResponseValidParse();
        PrintTestResult("EncryptJsonResponse valid parse", true);
    } catch (...) {
        PrintTestResult("EncryptJsonResponse valid parse", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptJsonResponseValidParse();
        PrintTestResult("DecryptJsonResponse valid parse", true);
    } catch (...) {
        PrintTestResult("DecryptJsonResponse valid parse", false);
        all_tests_passed = false;
    }
    
    try {
        test_JsonResponseInvalidJson();
        PrintTestResult("JsonResponse invalid JSON", true);
    } catch (...) {
        PrintTestResult("JsonResponse invalid JSON", false);
        all_tests_passed = false;
    }
    
    try {
        test_JsonResponseMissingRequiredFields();
        PrintTestResult("JsonResponse missing required fields", true);
    } catch (...) {
        PrintTestResult("JsonResponse missing required fields", false);
        all_tests_passed = false;
    }

    try {
        test_EncryptJsonResponseMissingEncryptedValue();
        PrintTestResult("EncryptJsonResponse missing encrypted value", true);
    } catch (...) {
        PrintTestResult("EncryptJsonResponse missing encrypted value", false);
        all_tests_passed = false;
    }

    try {
        test_DecryptJsonResponseMissingDecryptedValue();
        PrintTestResult("DecryptJsonResponse missing decrypted value", true);
    } catch (...) {
        PrintTestResult("DecryptJsonResponse missing decrypted value", false);
        all_tests_passed = false;
    }

    try {
        test_EncryptJsonResponseMissingEncryptedCompression();
        PrintTestResult("EncryptJsonResponse missing encrypted compression", true);
    } catch (...) {
        PrintTestResult("EncryptJsonResponse missing encrypted compression", false);
        all_tests_passed = false;
    }

    try {
        test_DecryptJsonResponseMissingDatatype();
        PrintTestResult("DecryptJsonResponse missing datatype", true);
    } catch (...) {
        PrintTestResult("DecryptJsonResponse missing datatype", false);
        all_tests_passed = false;
    }

    try {
        test_EncryptJsonResponseToJson();
        PrintTestResult("EncryptJsonResponse ToJson", true);
    } catch (...) {
        PrintTestResult("EncryptJsonResponse ToJson", false);
        all_tests_passed = false;
    }

    try {
        test_DecryptJsonResponseToJson();
        PrintTestResult("DecryptJsonResponse ToJson", true);
    } catch (...) {
        PrintTestResult("DecryptJsonResponse ToJson", false);
        all_tests_passed = false;
    }

    try {
        test_JsonResponsePartialParsing();
        PrintTestResult("JsonResponse partial parsing", true);
    } catch (...) {
        PrintTestResult("JsonResponse partial parsing", false);
        all_tests_passed = false;
    }

    try {
        test_JsonResponseEmptyStringHandling();
        PrintTestResult("JsonResponse empty string handling", true);
    } catch (...) {
        PrintTestResult("JsonResponse empty string handling", false);
        all_tests_passed = false;
    }

    try {
        test_JsonResponseNullJsonHandling();
        PrintTestResult("JsonResponse null json handling", true);
    } catch (...) {
        PrintTestResult("JsonResponse null json handling", false);
        all_tests_passed = false;
    }
    
    // datatype_length functionality tests - simplified
    try {
        test_DatatypeLengthParsing();
        PrintTestResult("Datatype length parsing", true);
    } catch (...) {
        PrintTestResult("Datatype length parsing", false);
        all_tests_passed = false;
    }
    
    try {
        test_DatatypeLengthSerialization();
        PrintTestResult("Datatype length serialization", true);
    } catch (...) {
        PrintTestResult("Datatype length serialization", false);
        all_tests_passed = false;
    }
    
    try {
        test_JsonRequestInvalidDatatypeLength();
        PrintTestResult("JsonRequest invalid datatype_length", true);
    } catch (...) {
        PrintTestResult("JsonRequest invalid datatype_length", false);
        all_tests_passed = false;
    }
    
    try {
        test_DecryptJsonResponseInvalidDatatypeLength();
        PrintTestResult("DecryptJsonResponse invalid datatype_length", true);
    } catch (...) {
        PrintTestResult("DecryptJsonResponse invalid datatype_length", false);
        all_tests_passed = false;
    }
    
    std::cout << "==================================" << std::endl;
    if (all_tests_passed) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests failed!" << std::endl;
        return 1;
    }
}

