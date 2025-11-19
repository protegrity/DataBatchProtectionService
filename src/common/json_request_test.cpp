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

#include <iostream>
#include <string>
#include <cassert>
#include <crow/app.h>
#include "json_request.h"
#include "enums.h"
#include <cppcodec/base64_rfc4648.hpp>
#include <gtest/gtest.h>

using namespace dbps::external;

// Helper function to convert base64 string to binary data for testing
std::vector<uint8_t> Base64ToBinary(const std::string& base64_str) {
    return cppcodec::base64_rfc4648::decode(base64_str);
}

// Helper function to convert binary data to base64 string for testing
std::string BinaryToBase64(const std::vector<uint8_t>& binary_data) {
    return cppcodec::base64_rfc4648::encode(binary_data);
}

// Helper function to convert a human-readable string to binary data (via base64)
// This simulates what happens in the real system: string -> base64 -> binary
std::vector<uint8_t> StringToBinary(const std::string& input_str) {
    std::string base64_str = cppcodec::base64_rfc4648::encode(input_str);
    return cppcodec::base64_rfc4648::decode(base64_str);
}

// Helper function to convert binary data back to a human-readable string
// This simulates what happens in the real system: binary -> base64 -> string
std::string BinaryToString(const std::vector<uint8_t>& binary_data) {
    std::string base64_str = cppcodec::base64_rfc4648::encode(binary_data);
    std::vector<uint8_t> decoded_bytes = cppcodec::base64_rfc4648::decode(base64_str);
    return std::string(decoded_bytes.begin(), decoded_bytes.end());
}

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
    "application_context": "{\"user_id\": \"user456\"}",
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
    "application_context": "{\"user_id\": \"user456\"}",
    "encryption_metadata": {
        "dbps_version": "v0.01"
    },
    "debug": {
        "reference_id": "ref789",
        "pretty_printed_value": "ENCRYPTED_test@example.com"
    }
})";

// Test cases for JsonRequest base class
TEST(JsonRequest, JsonRequestValidParse) {
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
    ASSERT_EQ(StringToBinary("test@example.com"), request.value_);
    
    ASSERT_TRUE(request.IsValid());
    ASSERT_EQ("", request.GetValidationError());
}

TEST(JsonRequest, JsonRequestMissingRequiredFields) {
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

TEST(JsonRequest, JsonRequestInvalidJson) {
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

TEST(JsonRequest, JsonRequestRequiredReferenceIdMissing) {
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
    ASSERT_EQ(std::vector<uint8_t>{}, request.value_);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("debug.reference_id") != std::string::npos);
}

// Test cases for EncryptJsonRequest
TEST(JsonRequest, EncryptJsonRequestValidParse) {
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
    ASSERT_EQ(StringToBinary("test@example.com"), request.value_);
    
    ASSERT_TRUE(request.IsValid());
    ASSERT_EQ("", request.GetValidationError());
}

TEST(JsonRequest, EncryptJsonRequestMissingValue) {
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
        "application_context": "{\"user_id\": \"user456\"}",
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
    ASSERT_EQ(std::vector<uint8_t>{}, request.value_);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("Missing required field: data_batch.value") != std::string::npos);
}

// Test cases for DecryptJsonRequest
TEST(JsonRequest, DecryptJsonRequestValidParse) {
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
    ASSERT_EQ(StringToBinary("ENCRYPTED_test@example.com"), request.encrypted_value_);
    
    // Verify encryption_metadata is parsed correctly
    ASSERT_EQ(1, request.encryption_metadata_.size());
    ASSERT_EQ("v0.01", request.encryption_metadata_.at("dbps_version"));
    
    ASSERT_TRUE(request.IsValid());
    ASSERT_EQ("", request.GetValidationError());
}

TEST(JsonRequest, DecryptJsonRequestMissingEncryptedValue) {
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
        "application_context": "{\"user_id\": \"user456\"}",
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
    ASSERT_EQ(std::vector<uint8_t>{}, request.encrypted_value_);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("Missing required field: data_batch_encrypted.value") != std::string::npos);
}

// Test SafeGetFromJsonPath functionality
TEST(JsonRequest, SafeGetFromJsonPathValid) {
    auto json_body = crow::json::load(VALID_ENCRYPT_JSON);
    ASSERT_TRUE(json_body);
    
    auto result = SafeGetFromJsonPath(json_body, {"column_reference", "name"});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ("email", *result);
    
    result = SafeGetFromJsonPath(json_body, {"data_batch", "value"});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ("dGVzdEBleGFtcGxlLmNvbQ==", *result); // "test@example.com"
}

TEST(JsonRequest, SafeGetFromJsonPathInvalidPath) {
    auto json_body = crow::json::load(VALID_ENCRYPT_JSON);
    ASSERT_TRUE(json_body);
    
    auto result = SafeGetFromJsonPath(json_body, {"nonexistent", "field"});
    ASSERT_FALSE(result.has_value());
    
    result = SafeGetFromJsonPath(json_body, {"column_reference", "nonexistent"});
    ASSERT_FALSE(result.has_value());
}

// Test JSON generation functionality
TEST(JsonRequest, EncryptJsonRequestToJson) {
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

TEST(JsonRequest, EncryptJsonRequestWithEncodingAttributes) {
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
        "application_context": "{\"user_id\": \"user456\"}",
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
    ASSERT_EQ(StringToBinary("test@example.com"), request.value_);
    
    // Verify encoding_attributes are parsed correctly
    ASSERT_EQ(3, request.encoding_attributes_.size());
    ASSERT_EQ("DATA_PAGE", request.encoding_attributes_["page_type"]);
    ASSERT_EQ("PLAIN", request.encoding_attributes_["page_encoding"]);
    ASSERT_EQ("1", request.encoding_attributes_["data_page_num_values"]);
    
    ASSERT_TRUE(request.IsValid());
}

TEST(JsonRequest, EncryptJsonRequestToJsonWithEncodingAttributes) {
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
    request.application_context_ = "{\"user_id\": \"user456\"}";
    request.value_ = StringToBinary("test@example.com");
    
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

TEST(JsonRequest, DecryptJsonRequestToJson) {
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
    
    // Verify encryption_metadata is included in the JSON output
    ASSERT_TRUE(json_string.find("encryption_metadata") != std::string::npos);
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
    },
    "encryption_metadata": {
        "dbps_version": "v0.01"
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
TEST(JsonRequest, EncryptJsonResponseValidParse) {
    EncryptJsonResponse response;
    response.Parse(VALID_ENCRYPT_RESPONSE_JSON);
    
    ASSERT_EQ("user456", response.user_id_);
    ASSERT_EQ("admin", response.role_);
    ASSERT_EQ("read_write", response.access_control_);
    ASSERT_EQ("ref789", response.reference_id_);
    ASSERT_EQ(CompressionCodec::GZIP, response.encrypted_compression_.value());
    ASSERT_EQ(StringToBinary("ENCRYPTED_test@example.com"), response.encrypted_value_);
    
    // Verify encryption_metadata is parsed correctly
    ASSERT_EQ(1, response.encryption_metadata_.size());
    ASSERT_EQ("v0.01", response.encryption_metadata_.at("dbps_version"));
    
    ASSERT_TRUE(response.IsValid());
    ASSERT_EQ("", response.GetValidationError());
}

TEST(JsonRequest, DecryptJsonResponseValidParse) {
    DecryptJsonResponse response;
    response.Parse(VALID_DECRYPT_RESPONSE_JSON);
    
    ASSERT_EQ("user456", response.user_id_);
    ASSERT_EQ("admin", response.role_);
    ASSERT_EQ("read_write", response.access_control_);
    ASSERT_EQ("ref789", response.reference_id_);
    ASSERT_EQ(Type::BYTE_ARRAY, response.datatype_.value());
    ASSERT_EQ(CompressionCodec::UNCOMPRESSED, response.compression_.value());
    ASSERT_EQ(Format::UNDEFINED, response.format_.value());
    ASSERT_EQ(StringToBinary("test@example.com"), response.decrypted_value_);
    
    ASSERT_TRUE(response.IsValid());
    ASSERT_EQ("", response.GetValidationError());
}

TEST(JsonRequest, JsonResponseInvalidJson) {
    EncryptJsonResponse response;
    response.Parse("invalid json");
    
    // Should handle invalid JSON gracefully
    ASSERT_FALSE(response.IsValid());
}

// JsonResponse test cases
TEST(JsonRequest, JsonResponseMissingRequiredFields) {
    TestableJsonResponse response;
    response.Parse("{}"); // Empty JSON
    
    ASSERT_FALSE(response.IsValid());
    std::string error = response.GetValidationError();
    ASSERT_TRUE(error.find("access.user_id") != std::string::npos);
    ASSERT_TRUE(error.find("access.role") != std::string::npos);
    ASSERT_TRUE(error.find("access.access_control") != std::string::npos);
    ASSERT_TRUE(error.find("debug.reference_id") != std::string::npos);
}

TEST(JsonRequest, EncryptJsonResponseMissingEncryptedValue) {
    EncryptJsonResponse response;
    response.Parse(R"({
        "access": {"user_id": "user123", "role": "admin", "access_control": "read"},
        "debug": {"reference_id": "ref456"},
        "data_batch_encrypted": {"value_format": {"compression": "GZIP"}}
    })");
    
    ASSERT_FALSE(response.IsValid());
    ASSERT_TRUE(response.GetValidationError().find("data_batch_encrypted.value") != std::string::npos);
}

TEST(JsonRequest, DecryptJsonResponseMissingDecryptedValue) {
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

TEST(JsonRequest, EncryptJsonResponseMissingEncryptedCompression) {
    EncryptJsonResponse response;
    response.Parse(R"({
        "access": {"user_id": "user123", "role": "admin", "access_control": "read"},
        "debug": {"reference_id": "ref456"},
        "data_batch_encrypted": {"value": "RU5DUllQVEVEX2RhdGE="} // "ENCRYPTED_data"
    })");
    
    ASSERT_FALSE(response.IsValid());
    ASSERT_TRUE(response.GetValidationError().find("data_batch_encrypted.value_format.compression") != std::string::npos);
}

TEST(JsonRequest, DecryptJsonResponseMissingDatatype) {
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

TEST(JsonRequest, EncryptJsonResponseToJson) {
    EncryptJsonResponse response;
    response.user_id_ = "user123";
    response.role_ = "admin";
    response.access_control_ = "read_write";
    response.reference_id_ = "ref456";
    response.encrypted_compression_ = CompressionCodec::GZIP;
    response.encrypted_value_ = StringToBinary("ENCRYPTED_data");
    response.encryption_metadata_["dbps_version"] = "v0.01";
    
    ASSERT_TRUE(response.IsValid());
    
    std::string json_string = response.ToJson();
    ASSERT_TRUE(json_string.find("user123") != std::string::npos);
    ASSERT_TRUE(json_string.find("admin") != std::string::npos);
    ASSERT_TRUE(json_string.find("read_write") != std::string::npos);
    ASSERT_TRUE(json_string.find("ref456") != std::string::npos);
    ASSERT_TRUE(json_string.find("RU5DUllQVEVEX2RhdGE=") != std::string::npos); // "ENCRYPTED_data"
    ASSERT_TRUE(json_string.find("GZIP") != std::string::npos);
    
    // Verify encryption_metadata is serialized correctly
    ASSERT_TRUE(json_string.find("encryption_metadata") != std::string::npos);
    ASSERT_TRUE(json_string.find("dbps_version") != std::string::npos);
    ASSERT_TRUE(json_string.find("v0.01") != std::string::npos);
}

TEST(JsonRequest, DecryptJsonResponseToJson) {
    DecryptJsonResponse response;
    response.user_id_ = "user123";
    response.role_ = "admin";
    response.access_control_ = "read_write";
    response.reference_id_ = "ref456";
    response.datatype_ = Type::BYTE_ARRAY;
    response.compression_ = CompressionCodec::UNCOMPRESSED;
    response.format_ = Format::UNDEFINED;
    response.decrypted_value_ = StringToBinary("decrypted_data");
    
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

TEST(JsonRequest, JsonResponsePartialParsing) {
    EncryptJsonResponse response;
    // value is "ENCRYPTED_data"
    response.Parse(R"({
        "access": {"user_id": "user123"},
        "data_batch_encrypted": {"value": "RU5DUllQVEVEX2RhdGE="}
    })");
    
    // Should parse what it can, but validation should fail
    ASSERT_EQ("user123", response.user_id_);
    ASSERT_EQ(StringToBinary("ENCRYPTED_data"), response.encrypted_value_);
    ASSERT_FALSE(response.IsValid()); // Missing other required fields
}

TEST(JsonRequest, JsonResponseEmptyStringHandling) {
    EncryptJsonResponse response;
    response.Parse("");
    
    ASSERT_FALSE(response.IsValid());
    // Should handle gracefully without crashing
}

TEST(JsonRequest, JsonResponseNullJsonHandling) {
    EncryptJsonResponse response;
    response.Parse("null");
    
    ASSERT_FALSE(response.IsValid());
    // Should handle gracefully without crashing
}

// Test datatype_length functionality - simplified
TEST(JsonRequest, DatatypeLengthParsing) {
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
        "application_context": "{\"user_id\": \"test_user\"}",
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

TEST(JsonRequest, DatatypeLengthSerialization) {
    // Test serialization with and without datatype_length
    TestableEncryptJsonRequest request;
    request.user_id_ = "test_user";
    request.reference_id_ = "test_ref_123";
    request.application_context_ = "{\"user_id\": \"test_user\"}";
    request.datatype_ = Type::FIXED_LEN_BYTE_ARRAY;
    request.datatype_length_ = 16;
    request.compression_ = CompressionCodec::UNCOMPRESSED;
    request.format_ = Format::PLAIN;
    request.encrypted_compression_ = CompressionCodec::UNCOMPRESSED;
    request.key_id_ = "test_key_123";
    request.value_ = StringToBinary("Hello, World!");
    
    std::string json_output = request.ToJsonString();
    auto json_obj = crow::json::load(json_output);
    ASSERT_TRUE(json_obj["data_batch"]["datatype_info"].has("length"));
    ASSERT_EQ(json_obj["data_batch"]["datatype_info"]["length"], 16);
}

// Test invalid datatype_length values
TEST(JsonRequest, JsonRequestInvalidDatatypeLength) {
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
        "application_context": "{\"user_id\": \"user456\"}",
        "debug": {"reference_id": "ref789"}
    })";
    
    EncryptJsonRequest request;
    request.Parse(json_with_invalid_datatype_length);
    
    ASSERT_FALSE(request.IsValid());
    std::string error = request.GetValidationError();
    ASSERT_TRUE(error.find("data_batch.datatype_info.length (invalid integer value)") != std::string::npos);
}

TEST(JsonRequest, DecryptJsonResponseInvalidDatatypeLength) {
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
