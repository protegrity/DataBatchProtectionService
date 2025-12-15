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

#include "parquet_utils.h"
#include "../common/exceptions.h"
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <variant>
#include <gtest/gtest.h>
#include "../common/bytes_utils.h"
#include "compression_utils.h"

using namespace dbps::external;
using namespace dbps::compression;

TEST(ParquetUtils, CalculateLevelBytesLength_DATA_PAGE_V2) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    AttributesMap attribs = {
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

TEST(ParquetUtils, CalculateLevelBytesLength_DICTIONARY_PAGE) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    AttributesMap attribs = {
        {"page_type", std::string("DICTIONARY_PAGE")}
    };
    int result = CalculateLevelBytesLength(raw, attribs);
    EXPECT_EQ(0, result);
}

TEST(ParquetUtils, CalculateLevelBytesLength_DATA_PAGE_V1_NoLevels) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};
    AttributesMap attribs = {
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

TEST(ParquetUtils, CalculateLevelBytesLength_DATA_PAGE_V1_WithLevels) {
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
    AttributesMap attribs = {
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

TEST(ParquetUtils, CalculateLevelBytesLength_DATA_PAGE_V1_InvalidEncoding) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};

    // Test DATA_PAGE_V1 with non-RLE encoding (should throw exception)
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(100)},
        {"data_page_max_repetition_level", int32_t(1)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("BIT_PACKED")},  // Not RLE
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), InvalidInputException);
}

TEST(ParquetUtils, CalculateLevelBytesLength_UnknownPageType) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03};

    // Test unknown page type (should throw exception)
    AttributesMap attribs = {
        {"page_type", std::string("UNKNOWN_PAGE_TYPE")}
    };
    EXPECT_THROW(CalculateLevelBytesLength(raw, attribs), InvalidInputException);
}

TEST(ParquetUtils, CalculateLevelBytesLength_InvalidTotalSize) {
    std::vector<uint8_t> raw = {0x01, 0x02};

    // Test DATA_PAGE_V2 with byte lengths exceeding raw data size (should throw exception)
    AttributesMap attribs = {
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

TEST(ParquetUtils, CalculateLevelBytesLength_NegativeTotalSize) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04};

    // Test DATA_PAGE_V2 with negative byte lengths (should throw exception)
    AttributesMap attribs = {
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


TEST(ParquetUtils, ParseValueBytesIntoTypedList_INT32) {
    std::vector<int32_t> values = {100, 200, 300};
    std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t*>(values.data()),
                               reinterpret_cast<const uint8_t*>(values.data()) + values.size() * sizeof(int32_t));
    
    TypedListValues result = ParseValueBytesIntoTypedList(bytes, Type::INT32, std::nullopt, Format::PLAIN);
    
    auto* int32_values = std::get_if<std::vector<int32_t>>(&result);
    ASSERT_NE(nullptr, int32_values);
    EXPECT_EQ(values, *int32_values);
}

TEST(ParquetUtils, ParseValueBytesIntoTypedList_INT64) {
    std::vector<int64_t> values = {1000, 2000};
    std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t*>(values.data()),
                               reinterpret_cast<const uint8_t*>(values.data()) + values.size() * sizeof(int64_t));
    
    TypedListValues result = ParseValueBytesIntoTypedList(bytes, Type::INT64, std::nullopt, Format::PLAIN);
    
    auto* int64_values = std::get_if<std::vector<int64_t>>(&result);
    ASSERT_NE(nullptr, int64_values);
    EXPECT_EQ(values, *int64_values);
}

TEST(ParquetUtils, ParseValueBytesIntoTypedList_BYTE_ARRAY) {
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

TEST(ParquetUtils, ParseValueBytesIntoTypedList_FIXED_LEN_BYTE_ARRAY) {
    std::vector<uint8_t> bytes = {'a', 'b', 'c', 'x', 'y', 'z'}; // Two 3-byte strings
    
    TypedListValues result = ParseValueBytesIntoTypedList(bytes, Type::FIXED_LEN_BYTE_ARRAY, 3, Format::PLAIN);
    
    auto* string_values = std::get_if<std::vector<std::string>>(&result);
    ASSERT_NE(nullptr, string_values);
    EXPECT_EQ(2, string_values->size());
    EXPECT_EQ("abc", (*string_values)[0]);
    EXPECT_EQ("xyz", (*string_values)[1]);
}

TEST(ParquetUtils, ParseValueBytesIntoTypedList_UnsupportedFormat) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04};
    EXPECT_THROW(ParseValueBytesIntoTypedList(bytes, Type::INT32, std::nullopt, Format::RLE), 
                 DBPSUnsupportedException);
}

TEST(ParquetUtils, ParseValueBytesIntoTypedList_BOOLEAN_Throws) {
    // BOOLEAN type is not supported for per-value parsing
    std::vector<uint8_t> bytes = {0xB4};  // 8 boolean values bit-packed
    EXPECT_THROW(ParseValueBytesIntoTypedList(bytes, Type::BOOLEAN, std::nullopt, Format::PLAIN),
                 DBPSUnsupportedException);
}

TEST(ParquetUtils, ParseValueBytesIntoTypedList_InvalidDataSize) {
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03}; // 3 bytes, not divisible by sizeof(int32_t)
    EXPECT_THROW(ParseValueBytesIntoTypedList(bytes, Type::INT32, std::nullopt, Format::PLAIN), 
                 InvalidInputException);
}

TEST(ParquetUtils, SliceValueBytesIntoRawBytes_INT32) {
    std::vector<uint8_t> bytes = {0x04,0x03,0x02,0x01, 0x0D,0x0C,0x0B,0x0A};
    auto out = SliceValueBytesIntoRawBytes(bytes, Type::INT32, std::nullopt, Format::PLAIN);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], (std::vector<uint8_t>{0x04,0x03,0x02,0x01}));
    EXPECT_EQ(out[1], (std::vector<uint8_t>{0x0D,0x0C,0x0B,0x0A}));
}

TEST(ParquetUtils, SliceValueBytesIntoRawBytes_BOOLEAN_Throws) {
    // BOOLEAN is bit-packed and not supported for per-value slicing
    std::vector<uint8_t> bytes = {0xB4};  // 8 boolean values bit-packed
    EXPECT_THROW(
        SliceValueBytesIntoRawBytes(bytes, Type::BOOLEAN, std::nullopt, Format::PLAIN),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, SliceValueBytesIntoRawBytes_BOOLEAN_MultipleBytes_Throws) {
    // Multiple bytes of boolean data
    std::vector<uint8_t> bytes = {0xFF, 0x00, 0xAA, 0x55};  // 32 boolean values
    EXPECT_THROW(
        SliceValueBytesIntoRawBytes(bytes, Type::BOOLEAN, std::nullopt, Format::PLAIN),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, SliceValueBytesIntoRawBytes_INT96) {
    std::vector<uint8_t> bytes = {
        0x01,0x02,0x03,0x04,
        0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C
    };
    auto out = SliceValueBytesIntoRawBytes(bytes, Type::INT96, std::nullopt, Format::PLAIN);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], bytes);
}

TEST(ParquetUtils, SliceValueBytesIntoRawBytes_BYTE_ARRAY) {
    std::vector<uint8_t> bytes;
    append_u32_le(bytes, 2);
    bytes.insert(bytes.end(), {'h','i'});
    append_u32_le(bytes, 3);
    bytes.insert(bytes.end(), {'x','y','z'});

    auto out = SliceValueBytesIntoRawBytes(bytes, Type::BYTE_ARRAY, std::nullopt, Format::PLAIN);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], (std::vector<uint8_t>{'h','i'}));
    EXPECT_EQ(out[1], (std::vector<uint8_t>{'x','y','z'}));
}

TEST(ParquetUtils, SliceValueBytesIntoRawBytes_BYTE_ARRAY_Truncated) {
    std::vector<uint8_t> bytes = {0x04,0x00,0x00,0x00, 'a','b','c'};
    EXPECT_THROW(
        SliceValueBytesIntoRawBytes(bytes, Type::BYTE_ARRAY, std::nullopt, Format::PLAIN),
        InvalidInputException);
}

TEST(ParquetUtils, SliceValueBytesIntoRawBytes_FixedSizeMisaligned) {
    std::vector<uint8_t> bytes = {0x00,0x01,0x02}; // not divisible by 8 for INT64
    EXPECT_THROW(
        SliceValueBytesIntoRawBytes(bytes, Type::INT64, std::nullopt, Format::PLAIN),
        InvalidInputException);
}

TEST(ParquetUtils, SliceValueBytesIntoRawBytes_UnsupportedFormat) {
    std::vector<uint8_t> bytes = {0x01,0x00,0x00,0x00};
    EXPECT_THROW(
        SliceValueBytesIntoRawBytes(bytes, Type::INT32, std::nullopt, Format::RLE),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, CombineRawBytesIntoValueBytes_INT32) {
    std::vector<RawValueBytes> elems = {
        {0x04,0x03,0x02,0x01},
        {0x0D,0x0C,0x0B,0x0A}
    };
    auto out = CombineRawBytesIntoValueBytes(elems, Type::INT32, std::nullopt, Format::PLAIN);
    EXPECT_EQ(out, (std::vector<uint8_t>{0x04,0x03,0x02,0x01, 0x0D,0x0C,0x0B,0x0A}));
}

TEST(ParquetUtils, CombineRawBytesIntoValueBytes_BOOLEAN_Throws) {
    // BOOLEAN is bit-packed and not supported for per-value combining
    std::vector<RawValueBytes> elems = {
        {0x01},  // single byte representing boolean value(s)
        {0x00}
    };
    EXPECT_THROW(
        CombineRawBytesIntoValueBytes(elems, Type::BOOLEAN, std::nullopt, Format::PLAIN),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, CombineRawBytesIntoValueBytes_BOOLEAN_EmptyInput_Throws) {
    // Even empty input should throw for BOOLEAN type
    std::vector<RawValueBytes> elems;
    EXPECT_THROW(
        CombineRawBytesIntoValueBytes(elems, Type::BOOLEAN, std::nullopt, Format::PLAIN),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, CombineRawBytesIntoValueBytes_BYTE_ARRAY) {
    std::vector<RawValueBytes> elems = {
        {'h','i'},
        {'x','y','z'}
    };
    auto out = CombineRawBytesIntoValueBytes(elems, Type::BYTE_ARRAY, std::nullopt, Format::PLAIN);
    // Expect [len=2][hi][len=3][xyz]
    std::vector<uint8_t> expected;
    append_u32_le(expected, 2);
    expected.insert(expected.end(), {'h','i'});
    append_u32_le(expected, 3);
    expected.insert(expected.end(), {'x','y','z'});
    EXPECT_EQ(out, expected);
}

TEST(ParquetUtils, CombineRawBytesIntoValueBytes_FIXED_LEN_BYTE_ARRAY_SizeMismatch) {
    // Expect length 3, but provide a 2-byte element -> should throw
    std::vector<RawValueBytes> elems = {
        {'a','b'},
        {'x','y','z'}
    };
    EXPECT_THROW(
        CombineRawBytesIntoValueBytes(elems, Type::FIXED_LEN_BYTE_ARRAY, 3, Format::PLAIN),
        InvalidInputException);
}

TEST(ParquetUtils, CombineRawBytesIntoValueBytes_UnsupportedFormat) {
    std::vector<RawValueBytes> elems = {
        {0x04,0x03,0x02,0x01}
    };
    EXPECT_THROW(
        CombineRawBytesIntoValueBytes(elems, Type::INT32, std::nullopt, Format::RLE),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, SliceAndCombine_RoundTrip_INT64) {
    // Two int64 values: little-endian bytes
    std::vector<uint8_t> bytes = {
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    auto sliced = SliceValueBytesIntoRawBytes(bytes, Type::INT64, std::nullopt, Format::PLAIN);
    auto combined = CombineRawBytesIntoValueBytes(sliced, Type::INT64, std::nullopt, Format::PLAIN);
    EXPECT_EQ(bytes, combined);
}

TEST(ParquetUtils, SliceAndCombine_RoundTrip_BYTE_ARRAY) {
    std::vector<uint8_t> bytes;
    append_u32_le(bytes, 3);
    bytes.insert(bytes.end(), {'f','o','o'});
    append_u32_le(bytes, 0); // empty string
    append_u32_le(bytes, 4);
    bytes.insert(bytes.end(), {'b','a','r','!'});

    auto sliced = SliceValueBytesIntoRawBytes(bytes, Type::BYTE_ARRAY, std::nullopt, Format::PLAIN);
    auto combined = CombineRawBytesIntoValueBytes(sliced, Type::BYTE_ARRAY, std::nullopt, Format::PLAIN);
    EXPECT_EQ(bytes, combined);
}

TEST(ParquetUtils, DecompressAndSplit_DataPageV2_Uncompressed) {
    AttributesMap attribs_conv = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(10)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(5)},
        {"page_v2_repetition_levels_byte_length", int32_t(0)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };

    std::vector<uint8_t> level_bytes = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> value_bytes = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0};
    std::vector<uint8_t> plaintext;
    plaintext.insert(plaintext.end(), level_bytes.begin(), level_bytes.end());
    plaintext.insert(plaintext.end(), value_bytes.begin(), value_bytes.end());

    auto result = DecompressAndSplit(
        plaintext, CompressionCodec::UNCOMPRESSED, attribs_conv);

    EXPECT_EQ(level_bytes, result.level_bytes);
    EXPECT_EQ(value_bytes, result.value_bytes);
}

TEST(ParquetUtils, DecompressAndSplit_DataPageV2_Compressed) {
    AttributesMap attribs_conv = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(10)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(5)},
        {"page_v2_repetition_levels_byte_length", int32_t(0)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", true}
    };

    std::vector<uint8_t> level_bytes = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> value_bytes = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0};
    std::vector<uint8_t> compressed_value_bytes = Compress(value_bytes, CompressionCodec::SNAPPY);

    std::vector<uint8_t> plaintext;
    plaintext.insert(plaintext.end(), level_bytes.begin(), level_bytes.end());
    plaintext.insert(plaintext.end(), compressed_value_bytes.begin(), compressed_value_bytes.end());

    auto result = DecompressAndSplit(
        plaintext, CompressionCodec::SNAPPY, attribs_conv);

    EXPECT_EQ(level_bytes, result.level_bytes);
    EXPECT_EQ(value_bytes, result.value_bytes);
}

TEST(ParquetUtils, DecompressAndSplit_DataPageV2_UnsupportedCompression) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(1)},
        {"data_page_max_definition_level", int32_t(0)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(0)},
        {"page_v2_repetition_levels_byte_length", int32_t(0)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", true}
    };

    std::vector<uint8_t> plaintext = {0x00};
    EXPECT_THROW(
        DecompressAndSplit(plaintext, CompressionCodec::LZO, attribs),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, CompressAndJoin_DataPageV1_Compressed) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(2)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(1)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    std::vector<uint8_t> level_bytes;
    append_u32_le(level_bytes, 2); // RLE block length
    level_bytes.insert(level_bytes.end(), {0x0A, 0x0B});
    std::vector<uint8_t> value_bytes = {0x21, 0x22, 0x23, 0x24};

    auto joined = CompressAndJoin(level_bytes, value_bytes, CompressionCodec::SNAPPY, attribs);
    auto expected = Compress(Join(level_bytes, value_bytes), CompressionCodec::SNAPPY);
    EXPECT_EQ(joined, expected);

    auto decomposed = DecompressAndSplit(joined, CompressionCodec::SNAPPY, attribs);
    EXPECT_EQ(decomposed.level_bytes, level_bytes);
    EXPECT_EQ(decomposed.value_bytes, value_bytes);
}

TEST(ParquetUtils, CompressAndJoin_DataPageV2_Uncompressed) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(3)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(2)},
        {"page_v2_repetition_levels_byte_length", int32_t(1)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", false}
    };

    std::vector<uint8_t> level_bytes = {0x10, 0x11, 0x12}; // 2+1
    std::vector<uint8_t> value_bytes = {0x21, 0x22, 0x23, 0x24};

    auto joined = CompressAndJoin(level_bytes, value_bytes, CompressionCodec::UNCOMPRESSED, attribs);
    std::vector<uint8_t> expected = Join(level_bytes, value_bytes);
    EXPECT_EQ(joined, expected);

    auto decomposed = DecompressAndSplit(joined, CompressionCodec::UNCOMPRESSED, attribs);
    EXPECT_EQ(decomposed.level_bytes, level_bytes);
    EXPECT_EQ(decomposed.value_bytes, value_bytes);
}

TEST(ParquetUtils, CompressAndJoin_DataPageV2_Compressed_RoundTrip) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(4)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(2)},
        {"page_v2_repetition_levels_byte_length", int32_t(1)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", true}
    };

    std::vector<uint8_t> level_bytes = {0x10, 0x11, 0x12}; // len matches 2+1
    std::vector<uint8_t> value_bytes = {0x21, 0x22, 0x23, 0x24, 0x25};

    auto joined = CompressAndJoin(level_bytes, value_bytes, CompressionCodec::SNAPPY, attribs);
    auto expected_compressed = Compress(value_bytes, CompressionCodec::SNAPPY);
    auto expected_joined = Join(level_bytes, expected_compressed);
    EXPECT_EQ(joined, expected_joined);

    auto decomposed = DecompressAndSplit(joined, CompressionCodec::SNAPPY, attribs);

    EXPECT_EQ(decomposed.level_bytes, level_bytes);
    EXPECT_EQ(decomposed.value_bytes, value_bytes);
}

TEST(ParquetUtils, CompressAndJoin_DataPageV2_LevelLengthMismatch) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V2")},
        {"data_page_num_values", int32_t(2)},
        {"data_page_max_definition_level", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"page_v2_definition_levels_byte_length", int32_t(2)},
        {"page_v2_repetition_levels_byte_length", int32_t(1)},
        {"page_v2_num_nulls", int32_t(0)},
        {"page_v2_is_compressed", true}
    };

    std::vector<uint8_t> level_bytes = {0x10, 0x11}; // expected 3 bytes -> mismatch
    std::vector<uint8_t> value_bytes = {0x21, 0x22, 0x23};

    EXPECT_THROW(
        CompressAndJoin(level_bytes, value_bytes, CompressionCodec::SNAPPY, attribs),
        InvalidInputException);
}

TEST(ParquetUtils, CompressAndJoin_DictionaryPage) {
    AttributesMap attribs = {
        {"page_type", std::string("DICTIONARY_PAGE")}
    };

    std::vector<uint8_t> level_bytes; // must be empty
    std::vector<uint8_t> value_bytes = {0x31, 0x32, 0x33};

    auto joined = CompressAndJoin(level_bytes, value_bytes, CompressionCodec::UNCOMPRESSED, attribs);
    EXPECT_EQ(joined, value_bytes);
}

TEST(ParquetUtils, CompressAndJoin_UnsupportedCompression) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(0)},
        {"data_page_max_definition_level", int32_t(0)},
        {"page_v1_repetition_level_encoding", std::string("RLE")},
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    std::vector<uint8_t> level_bytes;
    std::vector<uint8_t> value_bytes = {0x40};

    EXPECT_THROW(
        CompressAndJoin(level_bytes, value_bytes, CompressionCodec::LZO, attribs),
        DBPSUnsupportedException);
}

TEST(ParquetUtils, CompressAndJoin_UnsupportedEncoding) {
    AttributesMap attribs = {
        {"page_type", std::string("DATA_PAGE_V1")},
        {"data_page_num_values", int32_t(1)},
        {"data_page_max_repetition_level", int32_t(1)}, // triggers repetition level parsing
        {"data_page_max_definition_level", int32_t(0)},
        {"page_v1_repetition_level_encoding", std::string("BIT_PACKED")}, // unsupported
        {"page_v1_definition_level_encoding", std::string("RLE")}
    };

    // Build minimal level bytes that would be valid if encoding were RLE: len + payload
    std::vector<uint8_t> level_bytes;
    append_u32_le(level_bytes, 1);
    level_bytes.push_back(0x00);

    std::vector<uint8_t> value_bytes = {0x01, 0x02};

    EXPECT_THROW(
        CompressAndJoin(level_bytes, value_bytes, CompressionCodec::UNCOMPRESSED, attribs),
        InvalidInputException);
}
