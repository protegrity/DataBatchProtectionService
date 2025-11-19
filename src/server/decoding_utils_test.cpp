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

    // Test DATA_PAGE_V1 with non-RLE encoding (should fail)
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("BIT_PACKED")},  // Not RLE
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(-1, result); // Should fail due to invalid encoding type
}

TEST(DecodingUtils, CalculateLevelBytesLength_UnknownPageType) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03};

    // Test unknown page type
    std::map<std::string, std::variant<int32_t, bool, std::string>> attribs = {
        {"page_type", std::string("UNKNOWN_PAGE_TYPE")}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(-1, result);
}

TEST(DecodingUtils, CalculateLevelBytesLength_InvalidTotalSize) {
    std::vector<uint8_t> raw = {0x01, 0x02};

    // Test DATA_PAGE_V2 with byte lengths exceeding raw data size
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
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(-1, result);
}

TEST(DecodingUtils, CalculateLevelBytesLength_NegativeTotalSize) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};

    // Test DATA_PAGE_V2 with negative byte lengths
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
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(-1, result); // Total (4 bytes) is negative due to -5
}

// (Removed legacy wrappers; tests are native GTest cases above)
