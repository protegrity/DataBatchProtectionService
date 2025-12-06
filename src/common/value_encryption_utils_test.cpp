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
#include <string>
#include <array>
#include <limits>

using namespace dbps::value_encryption_utils;

TEST(ValueEncryptionUtilsTest, ConcatenateEncryptedValues_ParseConcatenatedEncryptedValues_RoundTrip) {
    std::vector<EncryptedValue> input;
    {
        std::vector<uint8_t> v1;
        v1.push_back(1);
        v1.push_back(2);
        v1.push_back(3);
        input.push_back(v1);
    }
    {
        std::vector<uint8_t> v2; // empty
        input.push_back(v2);
    }
    {
        std::vector<uint8_t> v3;
        v3.push_back(0xFF);
        input.push_back(v3);
    }

    std::vector<uint8_t> blob = ConcatenateEncryptedValues(input);
    std::vector<EncryptedValue> output = ParseConcatenatedEncryptedValues(blob);

    ASSERT_EQ(output.size(), input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        EXPECT_EQ(output[i], input[i]);
    }
}

// this is the main test.
 
TEST(ValueEncryptionUtilsTest, ParseConcatenatedEncryptedValues_MalformedMissingCount) {
    std::vector<uint8_t> blob;
    blob.push_back(0x01);
    blob.push_back(0x00); // only 2 bytes, need 4 for count
    EXPECT_THROW({
        (void)ParseConcatenatedEncryptedValues(blob);
    }, std::runtime_error);
}

TEST(ValueEncryptionUtilsTest, ParseConcatenatedEncryptedValues_MalformedTruncatedSizeField) {
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

TEST(ValueEncryptionUtilsTest, ParseConcatenatedEncryptedValues_MalformedTruncatedPayload) {
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

TEST(ValueEncryptionUtilsTest, EncryptTypedListValues_DecryptTypedListValues_RoundTrip_INT32) {
    // Identity "encryption/decryption" functions
    auto enc = [](const std::vector<uint8_t>& b) { return b; };
    auto dec = [](const std::vector<uint8_t>& b) { return b; };
    TypedListValues input = std::vector<int32_t>{10, 20, -30};
    auto encrypted = EncryptTypedListValues(input, enc);
    // Ensure declared sizes match the raw element sizes (4 per int32)
    ASSERT_EQ(encrypted.size(), 3u);
    for (const auto& ev : encrypted) {
        EXPECT_EQ(ev.size(), 4u);
    }
    auto decrypted = DecryptTypedListValues(encrypted, Type::INT32, dec);
    const auto& out_vec = std::get<std::vector<int32_t>>(decrypted);
    ASSERT_EQ(out_vec, std::get<std::vector<int32_t>>(input));
}

TEST(ValueEncryptionUtilsTest, ParseConcatenatedEncryptedValues_TrailingBytes) {
    // Build a valid blob for one element of size 1, then add an extra trailing byte
    std::vector<uint8_t> blob;
    // count = 1
    blob.push_back(0x01);
    blob.push_back(0x00);
    blob.push_back(0x00);
    blob.push_back(0x00);
    // size = 1
    blob.push_back(0x01);
    blob.push_back(0x00);
    blob.push_back(0x00);
    blob.push_back(0x00);
    // payload (1 byte)
    blob.push_back(0xAA);
    // trailing garbage
    blob.push_back(0xFF);
    EXPECT_THROW({
        (void)ParseConcatenatedEncryptedValues(blob);
    }, std::runtime_error);
}

TEST(ValueEncryptionUtilsTest, EncryptTypedListValues_DecryptTypedListValues_RoundTrip_FLOAT) {
    auto enc = [](const std::vector<uint8_t>& b) { return b; };
    auto dec = [](const std::vector<uint8_t>& b) { return b; };
    TypedListValues input = std::vector<float>{0.0f, -1.25f, 3.5f};
    auto encrypted = EncryptTypedListValues(input, enc);
    ASSERT_EQ(encrypted.size(), 3u);
    for (const auto& ev : encrypted) {
        EXPECT_EQ(ev.size(), 4u);
    }
    auto decrypted = DecryptTypedListValues(encrypted, Type::FLOAT, dec);
    const auto& out_vec = std::get<std::vector<float>>(decrypted);
    const auto& in_vec = std::get<std::vector<float>>(input);
    ASSERT_EQ(out_vec.size(), in_vec.size());
    for (size_t i = 0; i < in_vec.size(); ++i) {
        EXPECT_FLOAT_EQ(out_vec[i], in_vec[i]);
    }
}

TEST(ValueEncryptionUtilsTest, EncryptTypedListValues_DecryptTypedListValues_RoundTrip_INT64) {
    auto enc = [](const std::vector<uint8_t>& b) { return b; };
    auto dec = [](const std::vector<uint8_t>& b) { return b; };
    TypedListValues input = std::vector<int64_t>{0LL, -1LL, 0x1122334455667788LL};
    auto encrypted = EncryptTypedListValues(input, enc);
    ASSERT_EQ(encrypted.size(), 3u);
    for (const auto& ev : encrypted) {
        EXPECT_EQ(ev.size(), 8u);
    }
    auto decrypted = DecryptTypedListValues(encrypted, Type::INT64, dec);
    const auto& out_vec = std::get<std::vector<int64_t>>(decrypted);
    ASSERT_EQ(out_vec, std::get<std::vector<int64_t>>(input));
}

TEST(ValueEncryptionUtilsTest, EncryptTypedListValues_DecryptTypedListValues_RoundTrip_BYTE_ARRAY) {
    auto enc = [](const std::vector<uint8_t>& b) { return b; };
    auto dec = [](const std::vector<uint8_t>& b) { return b; };
    std::vector<std::string> strs = {"", "abc", std::string("\x00\xFF", 2)};
    TypedListValues input = strs;
    auto encrypted = EncryptTypedListValues(input, enc);
    ASSERT_EQ(encrypted.size(), strs.size());
    auto decrypted = DecryptTypedListValues(encrypted, Type::BYTE_ARRAY, dec);
    const auto& out_vec = std::get<std::vector<std::string>>(decrypted);
    ASSERT_EQ(out_vec, strs);
}

TEST(ValueEncryptionUtilsTest, EncryptTypedListValues_DecryptTypedListValues_RoundTrip_INT96) {
    auto enc = [](const std::vector<uint8_t>& b) { return b; };
    auto dec = [](const std::vector<uint8_t>& b) { return b; };
    std::vector<std::array<uint32_t, 3>> vals;
    vals.push_back({0u, 0u, 0u});
    vals.push_back({1u, 2u, 3u});
    TypedListValues input = vals;
    auto encrypted = EncryptTypedListValues(input, enc);
    ASSERT_EQ(encrypted.size(), vals.size());
    for (const auto& ev : encrypted) {
        EXPECT_EQ(ev.size(), 12u);
    }
    auto decrypted = DecryptTypedListValues(encrypted, Type::INT96, dec);
    const auto& out_vec = std::get<std::vector<std::array<uint32_t, 3>>>(decrypted);
    ASSERT_EQ(out_vec, vals);
}

TEST(ValueEncryptionUtilsTest, EncryptTypedListValues_DecryptTypedListValues_RoundTrip_UNDEFINED) {
    auto enc = [](const std::vector<uint8_t>& b) { return b; };
    auto dec = [](const std::vector<uint8_t>& b) { return b; };
    TypedListValues input = std::vector<uint8_t>{1u, 2u, 255u};
    auto encrypted = EncryptTypedListValues(input, enc);
    ASSERT_EQ(encrypted.size(), 3u);
    for (const auto& ev : encrypted) {
        EXPECT_EQ(ev.size(), 1u);
    }
    auto decrypted = DecryptTypedListValues(encrypted, Type::UNDEFINED, dec);
    const auto& out_vec = std::get<std::vector<uint8_t>>(decrypted);
    ASSERT_EQ(out_vec, std::get<std::vector<uint8_t>>(input));
}

TEST(ValueEncryptionUtilsTest, DecryptTypedListValues_InvalidDecryptedSize_Throws) {
    // Provide an encrypted value whose decrypted bytes are of incorrect size for FLOAT (expect 4, give 3)
    EncryptedValue ev = std::vector<uint8_t>{0x00, 0x00, 0x80}; // 3 bytes
    std::vector<EncryptedValue> values{ev};
    auto dec = [](const std::vector<uint8_t>& b) { return b; }; // identity
    EXPECT_THROW({
        (void)DecryptTypedListValues(values, Type::FLOAT, dec);
    }, std::runtime_error);
}

TEST(ValueEncryptionUtilsTest, EncryptTypedListValues_DecryptTypedListValues_InvokesCallbacks_ForEachElement) {
    // Prepare input
    TypedListValues input = std::vector<int32_t>{7, -3, 1024, 0};
    const size_t num_elems = std::get<std::vector<int32_t>>(input).size();

    // Counters to ensure callbacks are invoked once per element
    size_t enc_calls = 0;
    size_t dec_calls = 0;

    auto enc = [&](const std::vector<uint8_t>& b) {
        ++enc_calls;
        return b; // identity encryption
    };
    auto dec = [&](const std::vector<uint8_t>& b) {
        ++dec_calls;
        return b; // identity decryption
    };

    auto encrypted = EncryptTypedListValues(input, enc);
    EXPECT_EQ(enc_calls, num_elems);
    auto decrypted = DecryptTypedListValues(encrypted, Type::INT32, dec);
    EXPECT_EQ(dec_calls, num_elems);
    // Roundtrip correctness
    const auto& out_vec = std::get<std::vector<int32_t>>(decrypted);
    ASSERT_EQ(out_vec, std::get<std::vector<int32_t>>(input));
}

TEST(ValueEncryptionUtilsTest, EncryptTypedListValues_DecryptTypedListValues_XorRoundTrip) {
    // Use a simple XOR "encryption" for roundtrip verification
    const uint8_t key = 0x5Au;
    auto xor_fn = [&](const std::vector<uint8_t>& in) {
        std::vector<uint8_t> out(in);
        for (auto& v : out) v ^= key;
        return out;
    };

    // Use BYTE_ARRAY strings to exercise variable-length payloads
    std::vector<std::string> strs = {
        "", "A", "Hello", std::string("\x00\xFF\x10\x20", 4)
    };
    TypedListValues input = strs;

    auto encrypted = EncryptTypedListValues(input, xor_fn); // encrypt (xor)
    // Decrypt by applying same XOR again
    auto decrypted = DecryptTypedListValues(encrypted, Type::BYTE_ARRAY, xor_fn);
    const auto& out_vec = std::get<std::vector<std::string>>(decrypted);
    ASSERT_EQ(out_vec, strs);
}

TEST(ValueEncryptionUtilsTest, EncryptTypedListValues_DecryptTypedListValues_VarLenCiphertext_RoundTrip) {
    // Encrypt by doubling the bytes (append zeros of equal length)
    auto enc = [](const std::vector<uint8_t>& in) {
        std::vector<uint8_t> out;
        out.reserve(in.size() * 2);
        out.insert(out.end(), in.begin(), in.end());
        out.insert(out.end(), in.size(), static_cast<uint8_t>(0));
        return out;
    };
    // Decrypt by cutting the input bytes in half
    auto dec = [](const std::vector<uint8_t>& in) {
        const size_t half = in.size() / 2;
        return std::vector<uint8_t>(in.begin(), in.begin() + static_cast<std::ptrdiff_t>(half));
    };

    // Use BYTE_ARRAY strings to exercise variable-length plaintext and variable-length ciphertext
    std::vector<std::string> strs = {"", "A", "Hello", std::string("\x00\xFF\x10\x20", 4), std::string("0123456789", 10)};
    TypedListValues input = strs;

    auto encrypted = EncryptTypedListValues(input, enc);
    ASSERT_EQ(encrypted.size(), strs.size());
    // Ensure ciphertext length is exactly double the plaintext bytes length
    for (size_t i = 0; i < strs.size(); ++i) {
        const auto& ev = encrypted[i];
        EXPECT_EQ(ev.size(), std::get<std::vector<std::string>>(input)[i].size() * 2);
    }

    auto decrypted = DecryptTypedListValues(encrypted, Type::BYTE_ARRAY, dec);
    const auto& out_vec = std::get<std::vector<std::string>>(decrypted);
    ASSERT_EQ(out_vec, strs);
}
