#include <iostream>
#include <string>
#include <cassert>
#include "json_request.h"

// Test-specific derived class to access protected methods
class TestableJsonRequest : public JsonRequest {
public:
    // Implement the pure virtual method for testing
    void Parse(const std::string& request_body) override {
        ParseCommon(request_body);
    }
    
    // Implement the pure virtual ToJsonObject method for testing
    crow::json::wvalue ToJsonObject() const override {
        crow::json::wvalue json;
        json["test"] = "testable_request";
        return json;
    }
};

// Test-specific derived class for JsonResponse base class testing
class TestableJsonResponse : public JsonResponse {
public:
    // Implement the pure virtual ToJsonObject method for testing
    crow::json::wvalue ToJsonObject() const override {
        crow::json::wvalue json;
        json["test"] = "testable_response";
        return json;
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
    ASSERT_EQ("ref789", request.reference_id_);
    
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
    ASSERT_EQ("", request.reference_id_);
    
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
    ASSERT_EQ("", request.reference_id_);
    
    ASSERT_FALSE(request.IsValid());
}

TEST(JsonRequestRequiredReferenceIdMissing) {
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
    ASSERT_EQ("string", request.datatype_);
    ASSERT_EQ("none", request.compression_);
    ASSERT_EQ("text", request.format_);
    ASSERT_EQ("utf8", request.encoding_);
    ASSERT_EQ("gzip", request.encrypted_compression_);
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_EQ("ref789", request.reference_id_);
    
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
        },
        "debug": {
            "reference_id": "ref789"
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
    ASSERT_EQ("string", request.datatype_);
    ASSERT_EQ("none", request.compression_);
    ASSERT_EQ("text", request.format_);
    ASSERT_EQ("utf8", request.encoding_);
    ASSERT_EQ("gzip", request.encrypted_compression_);
    ASSERT_EQ("key123", request.key_id_);
    ASSERT_EQ("user456", request.user_id_);
    ASSERT_EQ("ref789", request.reference_id_);
    
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
        },
        "debug": {
            "reference_id": "ref789"
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
    ASSERT_EQ("test@example.com", *result);
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
    ASSERT_TRUE(json_string.find("test@example.com") != std::string::npos);
    ASSERT_TRUE(json_string.find("ref789") != std::string::npos);
    ASSERT_TRUE(json_string.find("key123") != std::string::npos);
    ASSERT_TRUE(json_string.find("user456") != std::string::npos);
}

TEST(DecryptJsonRequestToJson) {
    DecryptJsonRequest request;
    request.Parse(VALID_DECRYPT_JSON);
    
    ASSERT_TRUE(request.IsValid());
    
    // Generate JSON from the parsed object
    std::string json_string = request.ToJson();
    
    // Verify the generated JSON contains expected fields
    ASSERT_TRUE(json_string.find("email") != std::string::npos);
    ASSERT_TRUE(json_string.find("ENCRYPTED_test@example.com") != std::string::npos);
    ASSERT_TRUE(json_string.find("ref789") != std::string::npos);
    ASSERT_TRUE(json_string.find("key123") != std::string::npos);
    ASSERT_TRUE(json_string.find("user456") != std::string::npos);
}

// Test data for JsonResponse parsing
const std::string VALID_ENCRYPT_RESPONSE_JSON = R"({
    "data_batch_encrypted": {
        "value_format": {
            "compression": "gzip"
        },
        "value": "ENCRYPTED_test@example.com"
    },
    "access": {
        "user_id": "user456",
        "role": "admin",
        "access_control": "read_write"
    },
    "debug": {
        "reference_id": "ref789"
    }
})";

const std::string VALID_DECRYPT_RESPONSE_JSON = R"({
    "data_batch": {
        "datatype": "string",
        "value": "test@example.com",
        "value_format": {
            "compression": "none",
            "format": "text",
            "encoding": "utf8"
        }
    },
    "access": {
        "user_id": "user456",
        "role": "admin",
        "access_control": "read_write"
    },
    "debug": {
        "reference_id": "ref789"
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
    ASSERT_EQ("gzip", response.encrypted_compression_);
    ASSERT_EQ("ENCRYPTED_test@example.com", response.encrypted_value_);
    
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
    ASSERT_EQ("string", response.datatype_);
    ASSERT_EQ("none", response.compression_);
    ASSERT_EQ("text", response.format_);
    ASSERT_EQ("utf8", response.encoding_);
    ASSERT_EQ("test@example.com", response.decrypted_value_);
    
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
        "data_batch_encrypted": {"value_format": {"compression": "gzip"}}
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
            "datatype": "string",
            "value_format": {"compression": "none", "format": "text", "encoding": "utf8"}
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
        "data_batch_encrypted": {"value": "ENCRYPTED_data"}
    })");
    
    ASSERT_FALSE(response.IsValid());
    ASSERT_TRUE(response.GetValidationError().find("data_batch_encrypted.value_format.compression") != std::string::npos);
}

TEST(DecryptJsonResponseMissingDatatype) {
    DecryptJsonResponse response;
    response.Parse(R"({
        "access": {"user_id": "user123", "role": "admin", "access_control": "read"},
        "debug": {"reference_id": "ref456"},
        "data_batch": {
            "value": "decrypted_data",
            "value_format": {"compression": "none", "format": "text", "encoding": "utf8"}
        }
    })");
    
    ASSERT_FALSE(response.IsValid());
    ASSERT_TRUE(response.GetValidationError().find("data_batch.datatype") != std::string::npos);
}

TEST(EncryptJsonResponseToJson) {
    EncryptJsonResponse response;
    response.user_id_ = "user123";
    response.role_ = "admin";
    response.access_control_ = "read_write";
    response.reference_id_ = "ref456";
    response.encrypted_compression_ = "gzip";
    response.encrypted_value_ = "ENCRYPTED_data";
    
    ASSERT_TRUE(response.IsValid());
    
    std::string json_string = response.ToJson();
    ASSERT_TRUE(json_string.find("user123") != std::string::npos);
    ASSERT_TRUE(json_string.find("admin") != std::string::npos);
    ASSERT_TRUE(json_string.find("read_write") != std::string::npos);
    ASSERT_TRUE(json_string.find("ref456") != std::string::npos);
    ASSERT_TRUE(json_string.find("ENCRYPTED_data") != std::string::npos);
    ASSERT_TRUE(json_string.find("gzip") != std::string::npos);
}

TEST(DecryptJsonResponseToJson) {
    DecryptJsonResponse response;
    response.user_id_ = "user123";
    response.role_ = "admin";
    response.access_control_ = "read_write";
    response.reference_id_ = "ref456";
    response.datatype_ = "string";
    response.compression_ = "none";
    response.format_ = "text";
    response.encoding_ = "utf8";
    response.decrypted_value_ = "decrypted_data";
    
    ASSERT_TRUE(response.IsValid());
    
    std::string json_string = response.ToJson();
    ASSERT_TRUE(json_string.find("user123") != std::string::npos);
    ASSERT_TRUE(json_string.find("admin") != std::string::npos);
    ASSERT_TRUE(json_string.find("read_write") != std::string::npos);
    ASSERT_TRUE(json_string.find("ref456") != std::string::npos);
    ASSERT_TRUE(json_string.find("decrypted_data") != std::string::npos);
    ASSERT_TRUE(json_string.find("string") != std::string::npos);
    ASSERT_TRUE(json_string.find("none") != std::string::npos);
    ASSERT_TRUE(json_string.find("text") != std::string::npos);
    ASSERT_TRUE(json_string.find("utf8") != std::string::npos);
}

TEST(JsonResponsePartialParsing) {
    EncryptJsonResponse response;
    response.Parse(R"({
        "access": {"user_id": "user123"},
        "data_batch_encrypted": {"value": "ENCRYPTED_data"}
    })");
    
    // Should parse what it can, but validation should fail
    ASSERT_EQ("user123", response.user_id_);
    ASSERT_EQ("ENCRYPTED_data", response.encrypted_value_);
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
    

    
    std::cout << "==================================" << std::endl;
    if (all_tests_passed) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "Some tests failed!" << std::endl;
        return 1;
    }
}

