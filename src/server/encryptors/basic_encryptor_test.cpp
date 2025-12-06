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

#include "basic_encryptor.h"
#include "../../common/enums.h"
#include "../../common/exceptions.h"
#include "../decoding_utils.h"
#include <gtest/gtest.h>
#include <vector>

using namespace dbps::external;

TEST(BasicEncryptor, EncryptDecryptBlock_RoundTrip) {
    BasicEncryptor encryptor("test_key", "test_column", "test_user", "test_context", Type::BYTE_ARRAY);
    
    std::vector<uint8_t> original = {1, 2, 3, 4, 5, 10, 20, 30, 40, 50};
    std::vector<uint8_t> encrypted = encryptor.EncryptBlock(original);
    std::vector<uint8_t> decrypted = encryptor.DecryptBlock(encrypted);
    
    EXPECT_EQ(original, decrypted);
    EXPECT_NE(original, encrypted);
}

TEST(BasicEncryptor, EncryptBlock_EmptyData) {
    BasicEncryptor encryptor("test_key", "test_column", "test_user", "test_context", Type::BYTE_ARRAY);
    
    std::vector<uint8_t> empty;
    std::vector<uint8_t> encrypted = encryptor.EncryptBlock(empty);
    
    EXPECT_TRUE(encrypted.empty());
}

TEST(BasicEncryptor, EncryptBlock_DifferentKeys) {
    BasicEncryptor encryptor1("key1", "test_column", "test_user", "test_context", Type::BYTE_ARRAY);
    BasicEncryptor encryptor2("key2", "test_column", "test_user", "test_context", Type::BYTE_ARRAY);
    
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    std::vector<uint8_t> encrypted1 = encryptor1.EncryptBlock(data);
    std::vector<uint8_t> encrypted2 = encryptor2.EncryptBlock(data);
    
    EXPECT_NE(encrypted1, encrypted2);
}

TEST(BasicEncryptor, EncryptDecryptValueList_RoundTrip_INT32) {
    BasicEncryptor encryptor("test_key", "int32_column", "test_user", "test_context", Type::INT32);
    
    std::vector<int32_t> values = {0, -1, 1, 123456789, -123456789};
    TypedListValues typed_list = values;
    
    std::vector<uint8_t> encrypted_blob = encryptor.EncryptValueList(typed_list);
    TypedListValues decrypted_list = encryptor.DecryptValueList(encrypted_blob);
    
    auto* out = std::get_if<std::vector<int32_t>>(&decrypted_list);
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(values, *out);
}

TEST(BasicEncryptor, EncryptDecryptValueList_RoundTrip_DOUBLE) {
    BasicEncryptor encryptor("test_key", "double_column", "test_user", "test_context", Type::DOUBLE);
    
    std::vector<double> values = {0.0, -1.0, 1.0, 3.141592653589793, -2.718281828459045};
    TypedListValues typed_list = values;
    
    std::vector<uint8_t> encrypted_blob = encryptor.EncryptValueList(typed_list);
    TypedListValues decrypted_list = encryptor.DecryptValueList(encrypted_blob);
    
    auto* out = std::get_if<std::vector<double>>(&decrypted_list);
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(values, *out);
}

TEST(BasicEncryptor, EncryptDecryptValueList_RoundTrip_BYTE_ARRAY) {
    BasicEncryptor encryptor("test_key", "byte_array_column", "test_user", "test_context", Type::BYTE_ARRAY);
    
    std::vector<std::string> values = {"", "a", "hello", std::string("\x01\x02\x00\xFF", 4)};
    TypedListValues typed_list = values;
    
    std::vector<uint8_t> encrypted_blob = encryptor.EncryptValueList(typed_list);
    TypedListValues decrypted_list = encryptor.DecryptValueList(encrypted_blob);
    
    auto* out = std::get_if<std::vector<std::string>>(&decrypted_list);
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(values, *out);
}
