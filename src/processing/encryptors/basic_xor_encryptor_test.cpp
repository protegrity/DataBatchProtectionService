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

#include "basic_xor_encryptor.h"
#include "../../common/enums.h"
#include "../../common/exceptions.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <vector>

using namespace dbps::external;
using namespace dbps::processing;

TEST(BasicXorEncryptor, EncryptDecryptBlock_RoundTrip) {
    BasicXorEncryptor encryptor("test_key", "test_column", "test_user", "test_context", Type::BYTE_ARRAY);
    
    std::vector<uint8_t> original = {1, 2, 3, 4, 5, 10, 20, 30, 40, 50};
    std::vector<uint8_t> encrypted = encryptor.EncryptBlock(original);
    std::vector<uint8_t> decrypted = encryptor.DecryptBlock(encrypted);
    
    EXPECT_EQ(original, decrypted);
    EXPECT_NE(original, encrypted);
}

TEST(BasicXorEncryptor, EncryptBlock_EmptyData) {
    BasicXorEncryptor encryptor("test_key", "test_column", "test_user", "test_context", Type::BYTE_ARRAY);
    
    std::vector<uint8_t> empty;
    std::vector<uint8_t> encrypted = encryptor.EncryptBlock(empty);
    
    EXPECT_TRUE(encrypted.empty());
}

TEST(BasicXorEncryptor, EncryptBlock_DifferentKeys) {
    BasicXorEncryptor encryptor1("key1", "test_column", "test_user", "test_context", Type::BYTE_ARRAY);
    BasicXorEncryptor encryptor2("key2", "test_column", "test_user", "test_context", Type::BYTE_ARRAY);
    
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    std::vector<uint8_t> encrypted1 = encryptor1.EncryptBlock(data);
    std::vector<uint8_t> encrypted2 = encryptor2.EncryptBlock(data);
    
    EXPECT_NE(encrypted1, encrypted2);
}

TEST(BasicXorEncryptor, EncryptDecryptValueList_RoundTrip_INT32) {
    BasicXorEncryptor encryptor("test_key", "int32_column", "test_user", "test_context", Type::INT32);
    
    std::vector<int32_t> values = {0, -1, 1, 123456789, -123456789};
    TypedBufferI32 input_buffer_write(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        input_buffer_write.SetElement(i, values[i]);
    }

    // EncryptValueList currently traverses input via raw_elements()/iterators,
    // which are enabled for read buffers only. Finalize write buffer and
    // re-wrap bytes as a read buffer to match production read path behavior.
    std::vector<uint8_t> input_buffer_bytes = input_buffer_write.FinalizeAndTakeBuffer();
    const auto input_span = tcb::span<const uint8_t>(input_buffer_bytes.data(), input_buffer_bytes.size());
    TypedBufferI32 input_buffer_read{input_span};
    TypedValuesBuffer typed_buffer = std::move(input_buffer_read);

    std::vector<uint8_t> encrypted_blob = encryptor.EncryptValueList(typed_buffer);
    TypedValuesBuffer decrypted_buffer = encryptor.DecryptValueList(encrypted_blob);

    auto* out = std::get_if<TypedBufferI32>(&decrypted_buffer);
    ASSERT_NE(out, nullptr);
    ASSERT_EQ(values.size(), out->GetNumElements());
    for (size_t i = 0; i < values.size(); ++i) {
        EXPECT_EQ(values[i], out->GetElement(i));
    }
}

TEST(BasicXorEncryptor, EncryptDecryptValueList_RoundTrip_DOUBLE) {
    BasicXorEncryptor encryptor("test_key", "double_column", "test_user", "test_context", Type::DOUBLE);
    
    std::vector<double> values = {0.0, -1.0, 1.0, 3.141592653589793, -2.718281828459045};
    TypedBufferDouble input_buffer_write(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        input_buffer_write.SetElement(i, values[i]);
    }

    // EncryptValueList currently traverses input via raw_elements()/iterators,
    // which are enabled for read buffers only. Finalize write buffer and
    // re-wrap bytes as a read buffer to match production read path behavior.
    std::vector<uint8_t> input_buffer_bytes = input_buffer_write.FinalizeAndTakeBuffer();
    const auto input_span = tcb::span<const uint8_t>(input_buffer_bytes.data(), input_buffer_bytes.size());
    TypedBufferDouble input_buffer_read{input_span};
    TypedValuesBuffer typed_buffer = std::move(input_buffer_read);

    std::vector<uint8_t> encrypted_blob = encryptor.EncryptValueList(typed_buffer);
    TypedValuesBuffer decrypted_buffer = encryptor.DecryptValueList(encrypted_blob);

    auto* out = std::get_if<TypedBufferDouble>(&decrypted_buffer);
    ASSERT_NE(out, nullptr);
    ASSERT_EQ(values.size(), out->GetNumElements());
    for (size_t i = 0; i < values.size(); ++i) {
        EXPECT_EQ(values[i], out->GetElement(i));
    }
}

TEST(BasicXorEncryptor, EncryptDecryptValueList_RoundTrip_BYTE_ARRAY) {
    BasicXorEncryptor encryptor("test_key", "byte_array_column", "test_user", "test_context", Type::BYTE_ARRAY);
    
    std::vector<std::string> values = {"", "a", "hello", std::string("\x01\x02\x00\xFF", 4)};
    size_t reserved_bytes_hint = 0;
    for (const auto& value : values) {
        reserved_bytes_hint += value.size();
    }
    TypedBufferRawBytesVariableSized input_buffer_write(values.size(), reserved_bytes_hint, true);
    for (size_t i = 0; i < values.size(); ++i) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(values[i].data());
        input_buffer_write.SetElement(i, tcb::span<const uint8_t>(bytes, values[i].size()));
    }
    
    // EncryptValueList currently traverses input via raw_elements()/iterators,
    // which are enabled for read buffers only. Finalize write buffer and
    // re-wrap bytes as a read buffer to match production read path behavior.
    std::vector<uint8_t> input_buffer_bytes = input_buffer_write.FinalizeAndTakeBuffer();
    const auto input_span = tcb::span<const uint8_t>(input_buffer_bytes.data(), input_buffer_bytes.size());
    TypedBufferRawBytesVariableSized input_buffer_read{input_span};
    TypedValuesBuffer typed_buffer = std::move(input_buffer_read);

    std::vector<uint8_t> encrypted_blob = encryptor.EncryptValueList(typed_buffer);
    TypedValuesBuffer decrypted_buffer = encryptor.DecryptValueList(encrypted_blob);

    auto* out = std::get_if<TypedBufferRawBytesVariableSized>(&decrypted_buffer);
    ASSERT_NE(out, nullptr);
    ASSERT_EQ(values.size(), out->GetNumElements());
    for (size_t i = 0; i < values.size(); ++i) {
        const auto actual = out->GetElement(i);
        const auto* expected = reinterpret_cast<const uint8_t*>(values[i].data());
        const auto expected_span = tcb::span<const uint8_t>(expected, values[i].size());
        ASSERT_EQ(expected_span.size(), actual.size());
        EXPECT_TRUE(std::equal(expected_span.begin(), expected_span.end(), actual.begin()));
    }
}
