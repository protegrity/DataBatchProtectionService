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

#include "bytes_utils.h"
#include "exceptions.h"

#include <array>
#include <cmath>
#include <vector>
#include <variant>
#include <gtest/gtest.h>

TEST(BytesUtils, Split_Normal) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    BytesPair result = Split(bytes, 3);
    
    EXPECT_EQ(3, result.leading.size());
    EXPECT_EQ(3, result.trailing.size());
    EXPECT_EQ(std::vector<uint8_t>({0x01, 0x02, 0x03}), result.leading);
    EXPECT_EQ(std::vector<uint8_t>({0x04, 0x05, 0x06}), result.trailing);
}

TEST(BytesUtils, Split_AtBeginning) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    BytesPair result = Split(bytes, 0);
    
    EXPECT_EQ(0, result.leading.size());
    EXPECT_EQ(3, result.trailing.size());
    EXPECT_EQ(bytes, result.trailing);
}

TEST(BytesUtils, Split_AtEnd) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    BytesPair result = Split(bytes, 3);
    
    EXPECT_EQ(3, result.leading.size());
    EXPECT_EQ(0, result.trailing.size());
    EXPECT_EQ(bytes, result.leading);
}

TEST(BytesUtils, Split_InvalidIndex_Negative) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    EXPECT_THROW(Split(bytes, -1), InvalidInputException);
}

TEST(BytesUtils, Split_InvalidIndex_TooLarge) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
    EXPECT_THROW(Split(bytes, 4), InvalidInputException);
}

TEST(BytesUtils, Join_Normal) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> result = Join(leading, trailing);
    
    EXPECT_EQ(6, result.size());
    EXPECT_EQ(std::vector<uint8_t>({0x01, 0x02, 0x03, 0x04, 0x05, 0x06}), result);
}

TEST(BytesUtils, Join_EmptyLeading) {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> result = Join(leading, trailing);
    
    EXPECT_EQ(3, result.size());
    EXPECT_EQ(trailing, result);
}

TEST(BytesUtils, Join_EmptyTrailing) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing;
    std::vector<uint8_t> result = Join(leading, trailing);
    
    EXPECT_EQ(3, result.size());
    EXPECT_EQ(leading, result);
}

TEST(BytesUtils, Join_BothEmpty) {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing;
    std::vector<uint8_t> result = Join(leading, trailing);
    
    EXPECT_TRUE(result.empty());
}

TEST(BytesUtils, SplitAndJoin_RoundTrip) {
    std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    BytesPair split_result = Split(original, 3);
    std::vector<uint8_t> joined = Join(split_result.leading, split_result.trailing);
    
    EXPECT_EQ(original, joined);
}

TEST(BytesUtils, JoinWithLengthPrefix_Normal) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> result = JoinWithLengthPrefix(leading, trailing);
    
    // Expected: [0x03, 0x00, 0x00, 0x00] (length=3 in little-endian) + leading + trailing
    EXPECT_EQ(10, result.size()); // 4 bytes length + 3 bytes leading + 3 bytes trailing
    EXPECT_EQ(0x03, result[0]);
    EXPECT_EQ(0x00, result[1]);
    EXPECT_EQ(0x00, result[2]);
    EXPECT_EQ(0x00, result[3]);
    EXPECT_EQ(0x01, result[4]);
    EXPECT_EQ(0x02, result[5]);
    EXPECT_EQ(0x03, result[6]);
    EXPECT_EQ(0x04, result[7]);
    EXPECT_EQ(0x05, result[8]);
    EXPECT_EQ(0x06, result[9]);
}

TEST(BytesUtils, JoinWithLengthPrefix_EmptyLeading) {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> result = JoinWithLengthPrefix(leading, trailing);
    
    EXPECT_EQ(7, result.size()); // 4 bytes length + 0 leading + 3 trailing
    EXPECT_EQ(0x00, result[0]);
    EXPECT_EQ(0x00, result[1]);
    EXPECT_EQ(0x00, result[2]);
    EXPECT_EQ(0x00, result[3]);
    EXPECT_EQ(0x04, result[4]);
    EXPECT_EQ(0x05, result[5]);
    EXPECT_EQ(0x06, result[6]);
}

TEST(BytesUtils, JoinWithLengthPrefix_EmptyTrailing) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing;
    std::vector<uint8_t> result = JoinWithLengthPrefix(leading, trailing);
    
    EXPECT_EQ(7, result.size()); // 4 bytes length + 3 leading + 0 trailing
    EXPECT_EQ(0x03, result[0]);
    EXPECT_EQ(0x00, result[1]);
    EXPECT_EQ(0x00, result[2]);
    EXPECT_EQ(0x00, result[3]);
    EXPECT_EQ(0x01, result[4]);
    EXPECT_EQ(0x02, result[5]);
    EXPECT_EQ(0x03, result[6]);
}

TEST(BytesUtils, JoinWithLengthPrefix_BothEmpty) {
    std::vector<uint8_t> leading;
    std::vector<uint8_t> trailing;
    std::vector<uint8_t> result = JoinWithLengthPrefix(leading, trailing);
    
    EXPECT_EQ(4, result.size()); // only the 4-byte length prefix
    EXPECT_EQ(0x00, result[0]);
    EXPECT_EQ(0x00, result[1]);
    EXPECT_EQ(0x00, result[2]);
    EXPECT_EQ(0x00, result[3]);
}

TEST(BytesUtils, SplitWithLengthPrefix_Normal) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03};
    std::vector<uint8_t> trailing = {0x04, 0x05, 0x06};
    std::vector<uint8_t> combined = JoinWithLengthPrefix(leading, trailing);
    BytesPair result = SplitWithLengthPrefix(combined);
    
    EXPECT_EQ(leading, result.leading);
    EXPECT_EQ(trailing, result.trailing);
}

TEST(BytesUtils, SplitWithLengthPrefix_InvalidData_Short) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03}; // too short for length prefix
    EXPECT_THROW(SplitWithLengthPrefix(bytes), InvalidInputException);
}

TEST(BytesUtils, SplitWithLengthPrefix_InvalidData_TruncatedLeading) {
    // length=5 but only 4 bytes provided after prefix
    std::vector<uint8_t> bytes = {0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04};
    EXPECT_THROW(SplitWithLengthPrefix(bytes), InvalidInputException);
}

TEST(BytesUtils, SplitWithLengthPrefix_InvalidInsufficientData) {
    // Length prefix says 10 bytes, but we only have 4 bytes total
    std::vector<uint8_t> invalid = {0x0A, 0x00, 0x00, 0x00}; // length = 10, but only 4 bytes total
    EXPECT_THROW(SplitWithLengthPrefix(invalid), InvalidInputException);
}

TEST(BytesUtils, JoinWithLengthPrefixAndSplit_RoundTrip) {
    std::vector<uint8_t> leading = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> trailing = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    
    std::vector<uint8_t> joined = JoinWithLengthPrefix(leading, trailing);
    BytesPair parsed = SplitWithLengthPrefix(joined);
    
    EXPECT_EQ(leading, parsed.leading);
    EXPECT_EQ(trailing, parsed.trailing);
}

TEST(BytesUtils, AttributesMap_AddString) {
    std::map<std::string, std::string> attrs{{"page_type", "DATA_PAGE_V1"}};
    AttributesMap out;

    auto v = AddStringAttribute(out, attrs, "page_type");
    EXPECT_EQ("DATA_PAGE_V1", v);
    EXPECT_EQ("DATA_PAGE_V1", std::get<std::string>(out.at("page_type")));

    EXPECT_THROW(AddStringAttribute(out, attrs, "missing_key"), InvalidInputException);
}

TEST(BytesUtils, AttributesMap_AddInt) {
    std::map<std::string, std::string> attrs{{"data_page_num_values", "10"}};
    AttributesMap out;

    auto v = AddIntAttribute(out, attrs, "data_page_num_values");
    EXPECT_EQ(10, v);
    EXPECT_EQ(10, std::get<int32_t>(out.at("data_page_num_values")));

    std::map<std::string, std::string> bad_attrs{{"data_page_num_values", "abc"}};
    EXPECT_THROW(AddIntAttribute(out, bad_attrs, "data_page_num_values"), InvalidInputException);
}

TEST(BytesUtils, AttributesMap_AddBool) {
    std::map<std::string, std::string> attrs_true{{"page_v2_is_compressed", "true"}};
    AttributesMap out;
    auto v_true = AddBoolAttribute(out, attrs_true, "page_v2_is_compressed");
    EXPECT_TRUE(v_true);
    EXPECT_TRUE(std::get<bool>(out.at("page_v2_is_compressed")));

    std::map<std::string, std::string> attrs_false{{"page_v2_is_compressed", "false"}};
    auto v_false = AddBoolAttribute(out, attrs_false, "page_v2_is_compressed");
    EXPECT_FALSE(v_false);
    EXPECT_FALSE(std::get<bool>(out.at("page_v2_is_compressed")));

    std::map<std::string, std::string> bad_attrs{{"page_v2_is_compressed", "maybe"}};
    EXPECT_THROW(AddBoolAttribute(out, bad_attrs, "page_v2_is_compressed"), InvalidInputException);
}

TEST(BytesUtils, StringToBytes_AsciiText) {
    const std::string input = "dbps";
    const std::vector<uint8_t> result = StringToBytes(input);

    EXPECT_EQ((std::vector<uint8_t>{'d', 'b', 'p', 's'}), result);
}

TEST(BytesUtils, StringToBytes_EmptyString) {
    const std::string input;
    const std::vector<uint8_t> result = StringToBytes(input);

    EXPECT_TRUE(result.empty());
}

TEST(BytesUtils, StringToBytes_PreservesRawBytesAndNulls) {
    std::string input;
    input.push_back('D');
    input.push_back('B');
    input.push_back('P');
    input.push_back('S');
    input.push_back('\0');
    input.push_back('X');
    input.push_back('Y');
    input.push_back(static_cast<char>(0xFF));
    input.push_back(static_cast<char>(0x80));
    input.push_back('\0');
    input.push_back('Z');

    const std::vector<uint8_t> result = StringToBytes(input);
    const std::vector<uint8_t> expected = {
        static_cast<uint8_t>('D'),
        static_cast<uint8_t>('B'),
        static_cast<uint8_t>('P'),
        static_cast<uint8_t>('S'),
        static_cast<uint8_t>(0x00),
        static_cast<uint8_t>('X'),
        static_cast<uint8_t>('Y'),
        static_cast<uint8_t>(0xFF),
        static_cast<uint8_t>(0x80),
        static_cast<uint8_t>(0x00),
        static_cast<uint8_t>('Z')};

    EXPECT_EQ(expected, result);
}

TEST(BytesUtils, BytesToString_ConvertsAsciiEmptyAndRawBytes) {
    {
        const std::vector<uint8_t> bytes = {'d', 'b', 'p', 's'};
        const std::string result = BytesToString(tcb::span<const uint8_t>(bytes));
        EXPECT_EQ(result, "dbps");
    }

    {
        const std::vector<uint8_t> bytes;
        const std::string result = BytesToString(tcb::span<const uint8_t>(bytes));
        EXPECT_TRUE(result.empty());
    }

    {
        const std::vector<uint8_t> bytes = {
            static_cast<uint8_t>('D'),
            static_cast<uint8_t>('B'),
            static_cast<uint8_t>('P'),
            static_cast<uint8_t>('S'),
            static_cast<uint8_t>(0x00),
            static_cast<uint8_t>('X'),
            static_cast<uint8_t>('Y'),
            static_cast<uint8_t>(0xFF),
            static_cast<uint8_t>(0x80),
            static_cast<uint8_t>(0x00),
            static_cast<uint8_t>('Z')};
        const std::string result = BytesToString(tcb::span<const uint8_t>(bytes));
        const std::string expected = std::string{
            'D', 'B', 'P', 'S', '\0', 'X', 'Y',
            static_cast<char>(0xFF), static_cast<char>(0x80), '\0', 'Z'};
        EXPECT_EQ(result.size(), expected.size());
        EXPECT_EQ(result, expected);
    }
}

TEST(BytesUtils, ReadU32Le_FromPointer_DecodesLittleEndianBytes) {
    const std::array<uint8_t, 4> bytes = {0x78, 0x56, 0x34, 0x12};
    const uint32_t value = read_u32_le(bytes.data());

    EXPECT_EQ(value, 0x12345678u);
}

TEST(BytesUtils, ReadLeWriteLe_Int32_RoundTrip) {
    const int32_t original = -2147483000;
    std::array<uint8_t, sizeof(int32_t)> bytes{};

    write_le<int32_t>(original, bytes.data());
    const int32_t decoded = read_le<int32_t>(bytes.data());

    EXPECT_EQ(decoded, original);
}

TEST(BytesUtils, ReadLeWriteLe_Int64_RoundTrip) {
    const int64_t original = -9223372036854000000LL;
    std::array<uint8_t, sizeof(int64_t)> bytes{};

    write_le<int64_t>(original, bytes.data());
    const int64_t decoded = read_le<int64_t>(bytes.data());

    EXPECT_EQ(decoded, original);
}

TEST(BytesUtils, ReadLeWriteLe_Float_RoundTrip) {
    const float original = -12345.625f;
    std::array<uint8_t, sizeof(float)> bytes{};

    write_le<float>(original, bytes.data());
    const float decoded = read_le<float>(bytes.data());

    EXPECT_FLOAT_EQ(decoded, original);
}

TEST(BytesUtils, ReadLeWriteLe_Double_RoundTrip) {
    const double original = 9876543210.125;
    std::array<uint8_t, sizeof(double)> bytes{};

    write_le<double>(original, bytes.data());
    const double decoded = read_le<double>(bytes.data());

    EXPECT_DOUBLE_EQ(decoded, original);
}

TEST(BytesUtils, WriteReadU32Le_OffsetRoundTrip_VerifiesBytesAndGuards) {
    constexpr size_t kPrefix = 3u;
    constexpr size_t kValueSize = sizeof(uint32_t);
    constexpr size_t kSuffix = 5u;
    std::array<uint8_t, kPrefix + kValueSize + kSuffix> bytes;
    bytes.fill(0xDD);

    const uint32_t original = 0xD3A5C79Eu;
    write_u32_le(bytes.data() + kPrefix, original);
    const uint32_t decoded = read_u32_le(bytes.data() + kPrefix);

    for (size_t i = 0; i < kPrefix; ++i) {
        EXPECT_EQ(bytes[i], 0xDD);
    }
    for (size_t i = 0; i < kSuffix; ++i) {
        EXPECT_EQ(bytes[kPrefix + kValueSize + i], 0xDD);
    }
    EXPECT_EQ(bytes[kPrefix + 0], 0x9E);
    EXPECT_EQ(bytes[kPrefix + 1], 0xC7);
    EXPECT_EQ(bytes[kPrefix + 2], 0xA5);
    EXPECT_EQ(bytes[kPrefix + 3], 0xD3);
    EXPECT_EQ(decoded, original);
}

TEST(BytesUtils, WriteReadLeInt32_OffsetRoundTrip_VerifiesBytesAndGuards) {
    constexpr size_t kPrefix = 3u;
    constexpr size_t kValueSize = sizeof(int32_t);
    constexpr size_t kSuffix = 5u;
    std::array<uint8_t, kPrefix + kValueSize + kSuffix> bytes;
    bytes.fill(0xDD);

    const int32_t original = 0x6E91A2F3;
    write_le<int32_t>(original, bytes.data() + kPrefix);
    const int32_t decoded = read_le<int32_t>(bytes.data() + kPrefix);

    for (size_t i = 0; i < kPrefix; ++i) {
        EXPECT_EQ(bytes[i], 0xDD);
    }
    for (size_t i = 0; i < kSuffix; ++i) {
        EXPECT_EQ(bytes[kPrefix + kValueSize + i], 0xDD);
    }
    EXPECT_EQ(bytes[kPrefix + 0], 0xF3);
    EXPECT_EQ(bytes[kPrefix + 1], 0xA2);
    EXPECT_EQ(bytes[kPrefix + 2], 0x91);
    EXPECT_EQ(bytes[kPrefix + 3], 0x6E);
    EXPECT_EQ(decoded, original);
}

TEST(BytesUtils, WriteReadLeInt64_OffsetRoundTrip_VerifiesBytesAndGuards) {
    constexpr size_t kPrefix = 3u;
    constexpr size_t kValueSize = sizeof(int64_t);
    constexpr size_t kSuffix = 5u;
    std::array<uint8_t, kPrefix + kValueSize + kSuffix> bytes;
    bytes.fill(0xDD);

    const int64_t original = 0x0102030405060708LL;
    write_le<int64_t>(original, bytes.data() + kPrefix);
    const int64_t decoded = read_le<int64_t>(bytes.data() + kPrefix);

    for (size_t i = 0; i < kPrefix; ++i) {
        EXPECT_EQ(bytes[i], 0xDD);
    }
    for (size_t i = 0; i < kSuffix; ++i) {
        EXPECT_EQ(bytes[kPrefix + kValueSize + i], 0xDD);
    }
    EXPECT_EQ(bytes[kPrefix + 0], 0x08);
    EXPECT_EQ(bytes[kPrefix + 1], 0x07);
    EXPECT_EQ(bytes[kPrefix + 2], 0x06);
    EXPECT_EQ(bytes[kPrefix + 3], 0x05);
    EXPECT_EQ(bytes[kPrefix + 4], 0x04);
    EXPECT_EQ(bytes[kPrefix + 5], 0x03);
    EXPECT_EQ(bytes[kPrefix + 6], 0x02);
    EXPECT_EQ(bytes[kPrefix + 7], 0x01);
    EXPECT_EQ(decoded, original);
}

TEST(BytesUtils, WriteReadLeFloat_OffsetRoundTrip_VerifiesBytesAndGuards) {
    constexpr size_t kPrefix = 3u;
    constexpr size_t kValueSize = sizeof(float);
    constexpr size_t kSuffix = 5u;
    std::array<uint8_t, kPrefix + kValueSize + kSuffix> bytes;
    bytes.fill(0xDD);

    constexpr float kOriginal = -3.1415927f;
    write_le<float>(kOriginal, bytes.data() + kPrefix);
    const float decoded = read_le<float>(bytes.data() + kPrefix);

    for (size_t i = 0; i < kPrefix; ++i) {
        EXPECT_EQ(bytes[i], 0xDD);
    }
    for (size_t i = 0; i < kSuffix; ++i) {
        EXPECT_EQ(bytes[kPrefix + kValueSize + i], 0xDD);
    }
    EXPECT_FLOAT_EQ(decoded, kOriginal);
}

TEST(BytesUtils, WriteReadLeDouble_OffsetRoundTrip_VerifiesBytesAndGuards) {
    constexpr size_t kPrefix = 3u;
    constexpr size_t kValueSize = sizeof(double);
    constexpr size_t kSuffix = 5u;
    std::array<uint8_t, kPrefix + kValueSize + kSuffix> bytes;
    bytes.fill(0xDD);

    constexpr double kOriginal = -3.141592653589793;
    write_le<double>(kOriginal, bytes.data() + kPrefix);
    const double decoded = read_le<double>(bytes.data() + kPrefix);

    for (size_t i = 0; i < kPrefix; ++i) {
        EXPECT_EQ(bytes[i], 0xDD);
    }
    for (size_t i = 0; i < kSuffix; ++i) {
        EXPECT_EQ(bytes[kPrefix + kValueSize + i], 0xDD);
    }
    EXPECT_DOUBLE_EQ(decoded, kOriginal);
}
