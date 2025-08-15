#include <iostream>
#include <string>
#include <cassert>
#include "json_request.h"

// Test-specific derived class to access protected methods
class TestableJsonRequest : public JsonRequest {
public:
    using JsonRequest::SafeGetFromJsonPath; // Make protected method public for testing
    
    // Implement the pure virtual method for testing
    void Parse(const std::string& request_body) override {
        ParseCommon(request_body);
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
        "datatype": "string",
        "value": "test@example.com",
        "value_format": {
            "compression": "none",
            "format": "text",
            "encoding": "utf8"
        }
    },
    "data_batch_encrypted": {
        "value_format": {
            "compression": "gzip"
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

const std::string VALID_DECRYPT_JSON = R"({
    "column_reference": {
        "name": "email"
    },
    "data_batch": {
        "datatype": "string",
        "value_format": {
            "compression": "none",
            "format": "text",
            "encoding": "utf8"
        }
    },
    "data_batch_encrypted": {
        "value": "ENCRYPTED_test@example.com",
        "value_format": {
            "compression": "gzip"
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

// Test cases for JsonRequest base class
TEST(JsonRequestValidParse) {
    EncryptJsonRequest request;
    request.Parse(VALID_ENCRYPT_JSON);
    
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ("string", request.datatype_);
    ASSERT_EQ("none", request.compression_);
    ASSERT_EQ("text", request.format_);
    ASSERT_EQ("utf8", request.encoding_);
    ASSERT_EQ("gzip", request.encrypted_compression_);
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_TRUE(request.reference_id_.has_value());
    ASSERT_EQ("ref789", *request.reference_id_);
    
    // Check encrypt-specific field
    ASSERT_EQ("test@example.com", request.value_);
    
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
    ASSERT_EQ("", request.datatype_);
    ASSERT_EQ("", request.compression_);
    ASSERT_EQ("", request.format_);
    ASSERT_EQ("", request.encoding_);
    ASSERT_EQ("", request.encrypted_compression_);
    ASSERT_EQ("", request.key_id_);
    ASSERT_EQ("", request.user_id_);
    ASSERT_FALSE(request.reference_id_.has_value());
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("Missing required fields:") != std::string::npos);
    ASSERT_TRUE(error.find("data_batch.datatype") != std::string::npos);
    ASSERT_TRUE(error.find("encryption.key_id") != std::string::npos);
}

TEST(JsonRequestInvalidJson) {
    const std::string invalid_json = "{ invalid json }";
    
    EncryptJsonRequest request;
    request.Parse(invalid_json);
    
    // All fields should remain empty/default
    ASSERT_EQ("", request.column_name_);
    ASSERT_EQ("", request.datatype_);
    ASSERT_EQ("", request.compression_);
    ASSERT_EQ("", request.format_);
    ASSERT_EQ("", request.encoding_);
    ASSERT_EQ("", request.encrypted_compression_);
    ASSERT_EQ("", request.key_id_);
    ASSERT_EQ("", request.user_id_);
    ASSERT_FALSE(request.reference_id_.has_value());
    
    ASSERT_FALSE(request.IsValid());
}

TEST(JsonRequestOptionalReferenceIdMissing) {
    const std::string json_without_ref = R"({
        "column_reference": {
            "name": "email"
        },
        "data_batch": {
            "datatype": "string",
            "value_format": {
                "compression": "none",
                "format": "text",
                "encoding": "utf8"
            }
        },
        "data_batch_encrypted": {
            "value_format": {
                "compression": "gzip"
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
    ASSERT_EQ("string", request.datatype_);
    ASSERT_EQ("none", request.compression_);
    ASSERT_EQ("text", request.format_);
    ASSERT_EQ("utf8", request.encoding_);
    ASSERT_EQ("gzip", request.encrypted_compression_);
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_FALSE(request.reference_id_.has_value());
    
    // Check encrypt-specific field (should be empty since no value in JSON)
    ASSERT_EQ("", request.value_);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("Missing required field: data_batch.value") != std::string::npos);
}

// Test cases for EncryptJsonRequest
TEST(EncryptJsonRequestValidParse) {
    EncryptJsonRequest request;
    request.Parse(VALID_ENCRYPT_JSON);
    
    // Check common fields
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ("string", request.datatype_);
    ASSERT_EQ("none", request.compression_);
    ASSERT_EQ("text", request.format_);
    ASSERT_EQ("utf8", request.encoding_);
    ASSERT_EQ("gzip", request.encrypted_compression_);
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_TRUE(request.reference_id_.has_value());
    ASSERT_EQ("ref789", *request.reference_id_);
    
    // Check encrypt-specific fields
    ASSERT_EQ("test@example.com", request.value_);
    
    ASSERT_TRUE(request.IsValid());
    ASSERT_EQ("", request.GetValidationError());
}

TEST(EncryptJsonRequestMissingValue) {
    const std::string json_without_value = R"({
        "column_reference": {
            "name": "email"
        },
        "data_batch": {
            "datatype": "string",
            "value_format": {
                "compression": "none",
                "format": "text",
                "encoding": "utf8"
            }
        },
        "data_batch_encrypted": {
            "value_format": {
                "compression": "gzip"
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
    request.Parse(json_without_value);
    
    // Common fields should be parsed
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ("string", request.datatype_);
    ASSERT_EQ("none", request.compression_);
    ASSERT_EQ("text", request.format_);
    ASSERT_EQ("utf8", request.encoding_);
    ASSERT_EQ("gzip", request.encrypted_compression_);
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    
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
    ASSERT_EQ("string", request.datatype_);
    ASSERT_EQ("none", request.compression_);
    ASSERT_EQ("text", request.format_);
    ASSERT_EQ("utf8", request.encoding_);
    ASSERT_EQ("gzip", request.encrypted_compression_);
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_TRUE(request.reference_id_.has_value());
    ASSERT_EQ("ref789", *request.reference_id_);
    
    // Check decrypt-specific fields
    ASSERT_EQ("ENCRYPTED_test@example.com", request.encrypted_value_);
    
    ASSERT_TRUE(request.IsValid());
    ASSERT_EQ("", request.GetValidationError());
}

TEST(DecryptJsonRequestMissingEncryptedValue) {
    const std::string json_without_encrypted_value = R"({
        "column_reference": {
            "name": "email"
        },
        "data_batch": {
            "datatype": "string",
            "value_format": {
                "compression": "none",
                "format": "text",
                "encoding": "utf8"
            }
        },
        "data_batch_encrypted": {
            "value_format": {
                "compression": "gzip"
            }
        },
        "encryption": {
            "key_id": "key123"
        },
        "access": {
            "user_id": "user456"
        }
    })";
    
    DecryptJsonRequest request;
    request.Parse(json_without_encrypted_value);
    
    // Common fields should be parsed
    ASSERT_EQ("email", request.column_name_);
    ASSERT_EQ("string", request.datatype_);
    ASSERT_EQ("none", request.compression_);
    ASSERT_EQ("text", request.format_);
    ASSERT_EQ("utf8", request.encoding_);
    ASSERT_EQ("gzip", request.encrypted_compression_);
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    
    // Decrypt-specific field should be empty
    ASSERT_EQ("", request.encrypted_value_);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("Missing required field: data_batch_encrypted.value") != std::string::npos);
}

// Test SafeGetFromJsonPath functionality
TEST(SafeGetFromJsonPathValid) {
    TestableJsonRequest request;
    auto json_body = crow::json::load(VALID_ENCRYPT_JSON);
    ASSERT_TRUE(json_body);
    
    auto result = request.SafeGetFromJsonPath(json_body, {"column_reference", "name"});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ("email", *result);
    
    result = request.SafeGetFromJsonPath(json_body, {"data_batch", "value"});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ("test@example.com", *result);
}

TEST(SafeGetFromJsonPathInvalidPath) {
    TestableJsonRequest request;
    auto json_body = crow::json::load(VALID_ENCRYPT_JSON);
    ASSERT_TRUE(json_body);
    
    auto result = request.SafeGetFromJsonPath(json_body, {"nonexistent", "field"});
    ASSERT_FALSE(result.has_value());
    
    result = request.SafeGetFromJsonPath(json_body, {"column_reference", "nonexistent"});
    ASSERT_FALSE(result.has_value());
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
        test_JsonRequestOptionalReferenceIdMissing();
        PrintTestResult("JsonRequest optional reference_id missing", true);
    } catch (...) {
        PrintTestResult("JsonRequest optional reference_id missing", false);
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
    

    
    std::cout << "==================================" << std::endl;
    if (all_tests_passed) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests failed!" << std::endl;
        return 1;
    }
}
