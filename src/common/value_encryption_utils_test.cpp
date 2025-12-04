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

TEST(ValueEncryptionUtilsTest, ConcatenationEncryptionRoundTrip) {
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

static std::vector<uint8_t> serialize_i32_le(int32_t v) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    return out;
}
