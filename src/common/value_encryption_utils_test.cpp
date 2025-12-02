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

#include "value_encryption_utils.h"

#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include <variant>

namespace {

using namespace dbps::value_encryption_utils;

EncryptedValue make_ev(const std::vector<uint8_t>& bytes) {
    EncryptedValue ev;
    ev.payload = bytes;
    ev.size = bytes.size();
    return ev;
}

} // namespace

TEST(ValueEncryptionUtilsTest, EncryptValueInvertible) {
    std::vector<uint8_t> input;
    input.push_back(0x00);
    input.push_back(0x01);
    input.push_back(0xAA);
    input.push_back(0xFF);
    std::vector<uint8_t> key;
    key.push_back(0x5A);
    key.push_back(0xA5);

    EncryptedValue enc = EncryptValue(input, key);
    EXPECT_NE(enc.payload, input);

    std::vector<uint8_t> dec = DecryptValue(enc, key); 
    EXPECT_EQ(dec, input);
}

TEST(ValueEncryptionUtilsTest, EncryptValueEmpty) {
    std::vector<uint8_t> input;
    std::vector<uint8_t> key;
    key.push_back(0x00);
    EncryptedValue enc = EncryptValue(input, key);
    EXPECT_TRUE(enc.payload.empty());
    EXPECT_EQ(enc.size, 0u);
}

TEST(ValueEncryptionUtilsTest, EncryptValueEmptyKeyThrows) {
    std::vector<uint8_t> input;
    input.push_back(0x10);
    std::vector<uint8_t> empty_key;
    EXPECT_THROW({
        (void)EncryptValue(input, empty_key);
    }, std::invalid_argument);
}

TEST(ValueEncryptionUtilsTest, ConcatenationNoEncryptionRoundTrip) {
    std::vector<EncryptedValue> input;
    {
        std::vector<uint8_t> v1;
        v1.push_back(1);
        v1.push_back(2);
        v1.push_back(3);
        input.push_back(make_ev(v1));
    }
    {
        std::vector<uint8_t> v2; // empty
        input.push_back(make_ev(v2));
    }
    {
        std::vector<uint8_t> v3;
        v3.push_back(0xFF);
        input.push_back(make_ev(v3));
    }

    std::vector<uint8_t> blob = ConcatenateEncryptedValues(input);
    std::vector<EncryptedValue> output = ParseConcatenatedEncryptedValues(blob);

    ASSERT_EQ(output.size(), input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        EXPECT_EQ(output[i].size, input[i].size);
        EXPECT_EQ(output[i].payload, input[i].payload);
    }
}

// this is the main test.
TEST(ValueEncryptionUtilsTest, ConcatenationEncryptionRoundTrip) {
    // Key for encryption/decryption
    std::vector<uint8_t> key;
    key.push_back(0x12);
    key.push_back(0x34);
    key.push_back(0x56);

    // Plaintexts
    // 3 separate plaintexts: (a) an array of 10 bytes, (b) empty, (c) a single byte
    std::vector<std::vector<uint8_t>> plaintexts;
    plaintexts.push_back(std::vector<uint8_t>{0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01});
    plaintexts.push_back(std::vector<uint8_t>{});            // empty
    plaintexts.push_back(std::vector<uint8_t>{0xBB});

    // Encrypt each plaintext into EncryptedValue
    std::vector<EncryptedValue> encrypted_values;
    for (size_t i = 0; i < plaintexts.size(); ++i) {
        encrypted_values.push_back(EncryptValue(plaintexts[i], key));
    }

    // Concatenate encrypted values and parse back
    std::vector<uint8_t> encrypted_payload  = ConcatenateEncryptedValues(encrypted_values);
    std::vector<EncryptedValue> parsed_values = ParseConcatenatedEncryptedValues(encrypted_payload);

    // Validate
    ASSERT_EQ(parsed_values.size(), encrypted_values.size());
    for (size_t i = 0; i < encrypted_values.size(); ++i) {
        // Parsed encrypted values should match what we concatenated
        EXPECT_EQ(parsed_values[i].size, encrypted_values[i].size);
        EXPECT_EQ(parsed_values[i].payload, encrypted_values[i].payload);

        // Decrypt and compare with original plaintexts
        std::vector<uint8_t> decrypted = DecryptValue(parsed_values[i], key);
        EXPECT_EQ(decrypted, plaintexts[i]);
    }
}

TEST(ValueEncryptionUtilsTest, ConcatenateEncryptedValuesThrowsWhenPayloadSmallerThanSize) {
    // Construct an EncryptedValue with declared size larger than payload length
    EncryptedValue ev;
    ev.payload = std::vector<uint8_t>{0x01, 0x02};
    ev.size = 3u; // inconsistent on purpose

    std::vector<EncryptedValue> values;
    values.push_back(ev);

    EXPECT_THROW({
        (void)ConcatenateEncryptedValues(values);
    }, std::runtime_error);
}

TEST(ValueEncryptionUtilsTest, MalformedMissingCount) {
    std::vector<uint8_t> blob;
    blob.push_back(0x01);
    blob.push_back(0x00); // only 2 bytes, need 4 for count
    EXPECT_THROW({
        (void)ParseConcatenatedEncryptedValues(blob);
    }, std::runtime_error);
}

TEST(ValueEncryptionUtilsTest, MalformedTruncatedSizeField) {
    // count = 1
    std::vector<uint8_t> blob;
    blob.push_back(0x01);
    blob.push_back(0x00);
    blob.push_back(0x00);
    blob.push_back(0x00);
    // now we should have 4 bytes for size, but provide only 2
    blob.push_back(0x05);
    blob.push_back(0x00);
    EXPECT_THROW({
        (void)ParseConcatenatedEncryptedValues(blob);
    }, std::runtime_error);
}

TEST(ValueEncryptionUtilsTest, MalformedTruncatedPayload) {
    // count = 1
    std::vector<uint8_t> blob;
    blob.push_back(0x01);
    blob.push_back(0x00);
    blob.push_back(0x00);
    blob.push_back(0x00);
    // size = 5
    blob.push_back(0x05);
    blob.push_back(0x00);
    blob.push_back(0x00);
    blob.push_back(0x00);
    // only 3 bytes payload (should be 5)
    blob.push_back(0xAA);
    blob.push_back(0xBB);
    blob.push_back(0xCC);
    EXPECT_THROW({
        (void)ParseConcatenatedEncryptedValues(blob);
    }, std::runtime_error);
}

TEST(ValueEncryptionUtilsTest, AppendBuffersWithLengthWorks) {
    std::vector<std::vector<uint8_t> > buffers;
    buffers.push_back(std::vector<uint8_t>{0x01, 0x02, 0x03});
    buffers.push_back(std::vector<uint8_t>{}); // empty
    buffers.push_back(std::vector<uint8_t>{0xAA, 0xBB});

    std::vector<uint8_t> blob = ConcatenateBuffersWithLength(buffers);

    // Parse back with the inverse function
    std::vector<std::vector<uint8_t> > parsed = ParseBuffersWithLength(blob);
    ASSERT_EQ(parsed.size(), buffers.size());
    for (size_t i = 0; i < buffers.size(); ++i) {
        EXPECT_EQ(parsed[i], buffers[i]);
    }
}

static std::vector<uint8_t> serialize_i32_le(int32_t v) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    return out;
}

TEST(ValueEncryptionUtilsTest, EncryptTypedListValuesWithLevelBytesRoundTrip) {
    // Homogeneous TypedListValues: single int32_t vector
    TypedListValues elements = std::vector<int32_t>{10, -20, 30, -1};

    std::vector<uint8_t> level_bytes;
    level_bytes.push_back(0xAA);
    level_bytes.push_back(0xBB);
    level_bytes.push_back(0xCC);

    std::vector<uint8_t> key;
    key.push_back(0x12);
    key.push_back(0x34);

    // Encrypt values and attach level bytes
    std::vector<uint8_t> combined = EncryptTypedListValuesWithLevelBytes(elements, level_bytes, key);

    // Parse back the two buffers
    std::vector<std::vector<uint8_t> > buffers = ParseBuffersWithLength(combined);
    ASSERT_EQ(buffers.size(), 2u);

    const std::vector<uint8_t>& encrypted_values_blob = buffers[0];
    const std::vector<uint8_t>& parsed_level_bytes = buffers[1];
    EXPECT_EQ(parsed_level_bytes, level_bytes);

    // Parse encrypted values into EncryptedValue list
    std::vector<EncryptedValue> encrypted_values = ParseConcatenatedEncryptedValues(encrypted_values_blob);

    // Build expected serialized bytes for each original element (in order)
    std::vector<std::vector<uint8_t> > expected_serialized;
    expected_serialized.push_back(serialize_i32_le(10));
    expected_serialized.push_back(serialize_i32_le(-20));
    expected_serialized.push_back(serialize_i32_le(30));
    expected_serialized.push_back(serialize_i32_le(-1));

    ASSERT_EQ(encrypted_values.size(), expected_serialized.size());
    for (size_t i = 0; i < encrypted_values.size(); ++i) {
        std::vector<uint8_t> decrypted = DecryptValue(encrypted_values[i], key);
        EXPECT_EQ(decrypted, expected_serialized[i]);
    }
}

TEST(ValueEncryptionUtilsTest, DecryptTypedListValuesWithLevelBytesRoundTrip) {
    // Build inputs (single list)
    TypedListValues elements = std::vector<int32_t>{1, 2, 3, -7};

    std::vector<uint8_t> level_bytes;
    level_bytes.push_back(0x10);
    level_bytes.push_back(0x20);

    std::vector<uint8_t> key;
    key.push_back(0x11);
    key.push_back(0x22);

    // Encrypt+combine
    std::vector<uint8_t> combined = EncryptTypedListValuesWithLevelBytes(elements, level_bytes, key);

    // Decrypt+split
    std::pair<TypedListValues, std::vector<uint8_t> > result =
        DecryptTypedListValuesWithLevelBytes(combined, Type::INT32, key);

    // Validate level bytes
    EXPECT_EQ(result.second, level_bytes);

    // Validate values
    const std::vector<int32_t> expected = {1, 2, 3, -7};
    const std::vector<int32_t>& actual = std::get<std::vector<int32_t> >(result.first);
    EXPECT_EQ(actual, expected);
}

TEST(ValueEncryptionUtilsTest, ParseBuffersWithLengthMalformedTruncatedSize) {
    std::vector<uint8_t> blob;
    blob.push_back(0x02);
    blob.push_back(0x00); // only 2 bytes, need 4 for size
    EXPECT_THROW({
        (void)ParseBuffersWithLength(blob);
    }, std::runtime_error);
}

TEST(ValueEncryptionUtilsTest, ParseBuffersWithLengthMalformedTruncatedPayload) {
    std::vector<uint8_t> blob;
    // size = 3
    blob.push_back(0x03);
    blob.push_back(0x00);
    blob.push_back(0x00);
    blob.push_back(0x00);
    // only 2 bytes data
    blob.push_back(0xAA);
    blob.push_back(0xBB);
    EXPECT_THROW({
        (void)ParseBuffersWithLength(blob);
    }, std::runtime_error);
}


