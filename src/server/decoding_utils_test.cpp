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

#include "decoding_utils.h"
#include "exceptions.h"
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <variant>
#include <gtest/gtest.h>

using namespace dbps::external;

TEST(DecodingUtils, CalculateLevelBytesLength_DATA_PAGE_V2) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_definition_level", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"page_v2_definition_levels_byte_length", int32_t(1)},
        {"page_v2_repetition_levels_byte_length", int32_t(3)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(4, result); // 1 + 3 
}

TEST(DecodingUtils, CalculateLevelBytesLength_DICTIONARY_PAGE) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DICTIONARY_PAGE")}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(0, result);
}

TEST(DecodingUtils, CalculateLevelBytesLength_DATA_PAGE_V1_NoLevels) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(0)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(0, result);
}

TEST(DecodingUtils, CalculateLevelBytesLength_DATA_PAGE_V1_WithLevels) {
    std::vector<uint8_t> raw;

    // First RLE structure: 4-byte length + 8 bytes of data
    uint32_t len1 = 8;
    raw.resize(raw.size() + sizeof(uint32_t));
    std::memcpy(raw.data() + raw.size() - sizeof(uint32_t), &len1, sizeof(uint32_t));
    raw.insert(raw.end(), {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});

    // Second RLE structure: 4-byte length + 12 bytes of data  
    uint32_t len2 = 12;
    raw.resize(raw.size() + sizeof(uint32_t));
    std::memcpy(raw.data() + raw.size() - sizeof(uint32_t), &len2, sizeof(uint32_t));
    raw.insert(raw.end(), {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14});

    // Test DATA_PAGE_V1 with both repetition and definition levels
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(1)}, // > 0, so repetition levels present
        {"data_page_max_definition_level", int32_t(2)}, // > 0, so definition levels present
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(28, result); // (4+8) + (4+12) = 12 + 16 = 28
}

TEST(DecodingUtils, CalculateLevelBytesLength_DATA_PAGE_V1_InvalidEncoding) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};

    // Test DATA_PAGE_V1 with non-RLE encoding (should throw exception)
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("BIT_PACKED")},  // Not RLE
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), InvalidInputException);
}

TEST(DecodingUtils, CalculateLevelBytesLength_UnknownPageType) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03};

    // Test unknown page type (should throw exception)
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("UNKNOWN_PAGE_TYPE")}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), DBPSUnsupportedException);
}

TEST(DecodingUtils, CalculateLevelBytesLength_InvalidTotalSize) {
    std::vector<uint8_t> raw = {0x01, 0x02};

    // Test DATA_PAGE_V2 with byte lengths exceeding raw data size (should throw exception)
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_definition_level", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"page_v2_definition_levels_byte_length", int32_t(5)},
        {"page_v2_repetition_levels_byte_length", int32_t(3)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), InvalidInputException);
}

TEST(DecodingUtils, CalculateLevelBytesLength_NegativeTotalSize) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};

    // Test DATA_PAGE_V2 with negative byte lengths (should throw exception)
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_definition_level", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"page_v2_definition_levels_byte_length", int32_t(-1)},
        {"page_v2_repetition_levels_byte_length", int32_t(-5)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), InvalidInputException);
}


TEST(DecodingUtils, ParseValueBytesIntoTypedList_INT32) {
    std::vector<int32_t> values = {100, 200, 300};
    std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t*>(values.data()),
                               reinterpret_cast<const uint8_t*>(values.data()) + values.size() * sizeof(int32_t));
    
    TypedListValues result = ParseValueBytesIntoTypedList(bytes, Type::INT32, std::nullopt, Format::PLAIN);
    
    auto* int32_values = std::get_if<std::vector<int32_t>>(&result);
    ASSERT_NE(nullptr, int32_values);
    EXPECT_EQ(values, *int32_values);
}

TEST(DecodingUtils, ParseValueBytesIntoTypedList_INT64) {
    std::vector<int64_t> values = {1000, 2000};
    std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t*>(values.data()),
                               reinterpret_cast<const uint8_t*>(values.data()) + values.size() * sizeof(int64_t));
    
    TypedListValues result = ParseValueBytesIntoTypedList(bytes, Type::INT64, std::nullopt, Format::PLAIN);
    
    auto* int64_values = std::get_if<std::vector<int64_t>>(&result);
    ASSERT_NE(nullptr, int64_values);
    EXPECT_EQ(values, *int64_values);
}

TEST(DecodingUtils, ParseValueBytesIntoTypedList_BYTE_ARRAY) {
    std::vector<uint8_t> bytes;
    // First string: "hello" (length 5)
    uint32_t len1 = 5;
    bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&len1), 
                 reinterpret_cast<const uint8_t*>(&len1) + sizeof(len1));
    bytes.insert(bytes.end(), {'h', 'e', 'l', 'l', 'o'});
    // Second string: "world" (length 5)
    uint32_t len2 = 5;
    bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(&len2), 
                 reinterpret_cast<const uint8_t*>(&len2) + sizeof(len2));
    bytes.insert(bytes.end(), {'w', 'o', 'r', 'l', 'd'});
    
    TypedListValues result = ParseValueBytesIntoTypedList(bytes, Type::BYTE_ARRAY, std::nullopt, Format::PLAIN);
    
    auto* string_values = std::get_if<std::vector<std::string>>(&result);
    ASSERT_NE(nullptr, string_values);
    EXPECT_EQ(2, string_values->size());
    EXPECT_EQ("hello", (*string_values)[0]);
    EXPECT_EQ("world", (*string_values)[1]);
}

TEST(DecodingUtils, ParseValueBytesIntoTypedList_FIXED_LEN_BYTE_ARRAY) {
    std::vector<uint8_t> bytes = {'a', 'b', 'c', 'x', 'y', 'z'}; // Two 3-byte strings
    
    TypedListValues result = ParseValueBytesIntoTypedList(bytes, Type::FIXED_LEN_BYTE_ARRAY, 3, Format::PLAIN);
    
    auto* string_values = std::get_if<std::vector<std::string>>(&result);
    ASSERT_NE(nullptr, string_values);
    EXPECT_EQ(2, string_values->size());
    EXPECT_EQ("abc", (*string_values)[0]);
    EXPECT_EQ("xyz", (*string_values)[1]);
}

TEST(DecodingUtils, ParseValueBytesIntoTypedList_UnsupportedFormat) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
    EXPECT_THROW(ParseValueBytesIntoTypedList(bytes, Type::INT32, std::nullopt, Format::RLE), 
                 DBPSUnsupportedException);
}

TEST(DecodingUtils, ParseValueBytesIntoTypedList_InvalidDataSize) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03}; // 3 bytes, not divisible by sizeof(int32_t)
    EXPECT_THROW(ParseValueBytesIntoTypedList(bytes, Type::INT32, std::nullopt, Format::PLAIN), 
                 InvalidInputException);
}
