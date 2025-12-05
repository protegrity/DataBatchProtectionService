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

#include "typed_list_values.h"

#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include <variant>
#include <string>
#include <array>

using namespace dbps::external;

TEST(TypedListValuesTest, BuildRawBytesFromTypedListValues_BuildTypedListFromRawBytes_RoundTrip_INT32) {
    TypedListValues input = std::vector<int32_t>{0, 1, -1, 256, 123456789};
    std::vector<RawValueBytes> raw = BuildRawBytesFromTypedListValues(input);
    ASSERT_EQ(raw.size(), 5u);
    for (const auto& r : raw) {
        EXPECT_EQ(r.size(), 4u);
    }
    auto out = BuildTypedListFromRawBytes(Type::INT32, raw);
    const auto& out_vec = std::get<std::vector<int32_t>>(out);
    const auto& in_vec = std::get<std::vector<int32_t>>(input);
    ASSERT_EQ(out_vec, in_vec);
}

TEST(TypedListValuesTest, BuildRawBytesFromTypedListValues_BuildTypedListFromRawBytes_RoundTrip_INT64) {
    TypedListValues input = std::vector<int64_t>{0, 1, -1, 256, 0x1122334455667788LL};
    std::vector<RawValueBytes> raw = BuildRawBytesFromTypedListValues(input);
    ASSERT_EQ(raw.size(), 5u);
    for (const auto& r : raw) {
        EXPECT_EQ(r.size(), 8u);
    }
    auto out = BuildTypedListFromRawBytes(Type::INT64, raw);
    const auto& out_vec = std::get<std::vector<int64_t>>(out);
    const auto& in_vec = std::get<std::vector<int64_t>>(input);
    ASSERT_EQ(out_vec, in_vec);
}

TEST(TypedListValuesTest, BuildRawBytesFromTypedListValues_BuildTypedListFromRawBytes_RoundTrip_FLOAT) {
    TypedListValues input = std::vector<float>{0.0f, 1.5f, -2.25f, 12345.0f};
    std::vector<RawValueBytes> raw = BuildRawBytesFromTypedListValues(input);
    ASSERT_EQ(raw.size(), 4u);
    for (const auto& r : raw) {
        EXPECT_EQ(r.size(), 4u);
    }
    auto out = BuildTypedListFromRawBytes(Type::FLOAT, raw);
    const auto& out_vec = std::get<std::vector<float>>(out);
    const auto& in_vec = std::get<std::vector<float>>(input);
    ASSERT_EQ(out_vec.size(), in_vec.size());
    for (size_t i = 0; i < in_vec.size(); ++i) {
        EXPECT_FLOAT_EQ(out_vec[i], in_vec[i]);
    }
}

TEST(TypedListValuesTest, BuildRawBytesFromTypedListValues_BuildTypedListFromRawBytes_RoundTrip_DOUBLE) {
    TypedListValues input = std::vector<double>{0.0, 1.5, -2.25, 12345.0};
    std::vector<RawValueBytes> raw = BuildRawBytesFromTypedListValues(input);
    ASSERT_EQ(raw.size(), 4u);
    for (const auto& r : raw) {
        EXPECT_EQ(r.size(), 8u);
    }
    auto out = BuildTypedListFromRawBytes(Type::DOUBLE, raw);
    const auto& out_vec = std::get<std::vector<double>>(out);
    const auto& in_vec = std::get<std::vector<double>>(input);
    ASSERT_EQ(out_vec.size(), in_vec.size());
    for (size_t i = 0; i < in_vec.size(); ++i) {
        EXPECT_DOUBLE_EQ(out_vec[i], in_vec[i]);
    }
}

TEST(TypedListValuesTest, BuildRawBytesFromTypedListValues_BuildTypedListFromRawBytes_RoundTrip_INT96) {
    std::vector<std::array<uint32_t, 3>> vals;
    vals.push_back({0u, 0u, 0u});
    vals.push_back({1u, 2u, 3u});
    vals.push_back({0x11223344u, 0x55667788u, 0xAABBCCDDu});
    TypedListValues input = vals;
    std::vector<RawValueBytes> raw = BuildRawBytesFromTypedListValues(input);
    ASSERT_EQ(raw.size(), vals.size());
    for (const auto& r : raw) {
        EXPECT_EQ(r.size(), 12u);
    }
    auto out = BuildTypedListFromRawBytes(Type::INT96, raw);
    const auto& out_vec = std::get<std::vector<std::array<uint32_t, 3>>>(out);
    ASSERT_EQ(out_vec, vals);
}

TEST(TypedListValuesTest, BuildRawBytesFromTypedListValues_BuildTypedListFromRawBytes_RoundTrip_BYTE_ARRAY_and_FIXED) {
    std::vector<std::string> strs = {"", "a", "hello", std::string("\x00\x01\x02", 3)};
    {
        TypedListValues input = strs;
        auto raw = BuildRawBytesFromTypedListValues(input);
        ASSERT_EQ(raw.size(), strs.size());
        for (size_t i = 0; i < strs.size(); ++i) {
            EXPECT_EQ(std::string(reinterpret_cast<const char*>(raw[i].data()), raw[i].size()), strs[i]);
        }
        auto out = BuildTypedListFromRawBytes(Type::BYTE_ARRAY, raw);
        const auto& out_vec = std::get<std::vector<std::string>>(out);
        ASSERT_EQ(out_vec, strs);
    }
    {
        // Same raw used with FIXED_LEN_BYTE_ARRAY path (treated equivalently here)
        TypedListValues input = strs;
        auto raw = BuildRawBytesFromTypedListValues(input);
        auto out = BuildTypedListFromRawBytes(Type::FIXED_LEN_BYTE_ARRAY, raw);
        const auto& out_vec = std::get<std::vector<std::string>>(out);
        ASSERT_EQ(out_vec, strs);
    }
}

TEST(TypedListValuesTest, BuildRawBytesFromTypedListValues_BuildTypedListFromRawBytes_RoundTrip_UNDEFINED) {
    TypedListValues input = std::vector<uint8_t>{0u, 255u, 42u};
    std::vector<RawValueBytes> raw = BuildRawBytesFromTypedListValues(input);
    ASSERT_EQ(raw.size(), 3u);
    for (const auto& r : raw) {
        EXPECT_EQ(r.size(), 1u);
    }
    auto out = BuildTypedListFromRawBytes(Type::UNDEFINED, raw);
    const auto& out_vec = std::get<std::vector<uint8_t>>(out);
    const auto& in_vec = std::get<std::vector<uint8_t>>(input);
    ASSERT_EQ(out_vec, in_vec);
}

TEST(TypedListValuesTest, BuildTypedListFromRawBytes_InvalidElementSizes_Throws) {
    // INT32 wrong size
    {
        RawValueBytes r = {0x01, 0x02};
        std::vector<RawValueBytes> v{r};
        EXPECT_THROW((void)BuildTypedListFromRawBytes(Type::INT32, v), std::runtime_error);
    }
    // INT64 wrong size
    {
        RawValueBytes r = {0x01, 0x02, 0x03};
        std::vector<RawValueBytes> v{r};
        EXPECT_THROW((void)BuildTypedListFromRawBytes(Type::INT64, v), std::runtime_error);
    }
    // FLOAT wrong size
    {
        RawValueBytes r = {0x00, 0x00, 0x80};
        std::vector<RawValueBytes> v{r};
        EXPECT_THROW((void)BuildTypedListFromRawBytes(Type::FLOAT, v), std::runtime_error);
    }
    // DOUBLE wrong size
    {
        RawValueBytes r = {0x00, 0x00, 0x00, 0x00};
        std::vector<RawValueBytes> v{r};
        EXPECT_THROW((void)BuildTypedListFromRawBytes(Type::DOUBLE, v), std::runtime_error);
    }
    // INT96 wrong size
    {
        RawValueBytes r = RawValueBytes(11, 0);
        std::vector<RawValueBytes> v{r};
        EXPECT_THROW((void)BuildTypedListFromRawBytes(Type::INT96, v), std::runtime_error);
    }
    // UNDEFINED wrong size (expects exactly 1)
    {
        RawValueBytes r = {0xAA, 0xBB};
        std::vector<RawValueBytes> v{r};
        EXPECT_THROW((void)BuildTypedListFromRawBytes(Type::UNDEFINED, v), std::runtime_error);
    }
}

TEST(TypedListValuesTest, BuildTypedListFromRawBytes_UnsupportedType_Throws) {
    std::vector<RawValueBytes> raw; // empty ok; type unsupported should still throw
    EXPECT_THROW({
        (void)BuildTypedListFromRawBytes(Type::BOOLEAN, raw);
    }, std::runtime_error);
}

